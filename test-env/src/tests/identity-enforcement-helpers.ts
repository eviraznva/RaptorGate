import { performCommand, request } from "../harness";
import { createDefaultSnapshotBundle } from "../harness/fixtures";
import { sshWithResult, type KnownHost } from "../ssh-helper";

const BACKEND_API = "https://127.0.0.1:3000";
const PORTAL_API = "https://192.168.10.254/api/identity";
const H1_SOURCE_IP = "192.168.10.10";

type IdentityProfile = { id: string; name: string };
type IdentityConfig = {
	radiusServerProfiles: IdentityProfile[];
	ldapServerProfiles: IdentityProfile[];
	authenticationProfiles: IdentityProfile[];
	settings: {
		portalAuthenticationProfileId: string | null;
		adminAuthenticationProfileId: string | null;
		portalListener: {
			enabled: boolean;
			interfaceName: string | null;
			zoneId: string | null;
			bindAddress: string | null;
			bindPort: number;
		};
	};
};

type RadiusProfileInput = {
	name: string;
	description: string;
	isActive: boolean;
	host: string;
	port: number;
	sharedSecretRef: string;
	timeoutMs: number;
	retries: number;
	nasIp: string | null;
	nasIdentifier: string | null;
	calledStationId: string | null;
};

type LdapProfileInput = {
	name: string;
	description: string;
	isActive: boolean;
	host: string;
	port: number;
	tlsMode: "disabled" | "starttls" | "ldaps";
	bindDn: string;
	bindPasswordRef: string;
	userBaseDn: string;
	userFilterAttribute: string;
	groupBaseDn: string;
	groupMemberAttribute: string;
	groupNameAttribute: string;
	timeoutMs: number;
	cacheTtlSeconds: number;
};

type AuthProfileInput = {
	name: string;
	description: string;
	isActive: boolean;
	provider: "radius" | "ldap" | "local";
	radiusProfileId: string | null;
	ldapProfileId: string | null;
	groupSource: "none" | "ldap" | "radius_vsa";
	sessionTtlSeconds: number;
	adminRoleMappings: unknown[];
};

function shellQuote(value: string): string {
	return "'" + value.replace(/'/g, "'\\''") + "'";
}

async function sshOutput(host: KnownHost, command: string): Promise<string> {
	const result = await sshWithResult(host, command);
	if (result.exitCode !== 0) {
		throw new Error(
			`command failed on ${host} (exit ${result.exitCode}): ${result.stderr || result.stdout}`,
		);
	}
	return result.stdout;
}

async function backendJson<T>(
	method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
	path: string,
	body?: unknown,
	token?: string,
): Promise<T> {
	const auth = token
		? ` -H ${shellQuote(`authorization: Bearer ${token}`)}`
		: "";
	const contentType =
		body === undefined
			? ""
			: ` -H ${shellQuote("content-type: application/json")} -d ${shellQuote(JSON.stringify(body))}`;
	const command = `curl -k -sS --max-time 10 -X ${method}${auth}${contentType} ${shellQuote(`${BACKEND_API}${path}`)}`;
	const raw = (await sshOutput("r1", command)).trim();
	const parsed = JSON.parse(raw);
	if (typeof parsed?.statusCode === "number" && parsed.statusCode >= 400) {
		throw new Error(`backend ${method} ${path} failed: ${raw}`);
	}
	return parsed.data as T;
}

export async function adminAccessToken(): Promise<string> {
	const passwords = ["Test1234", "admin", "admin1234"];
	let lastError: unknown = null;

	for (const password of passwords) {
		try {
			const response = await backendJson<{ accessToken: string }>(
				"POST",
				"/auth/login",
				{ username: "admin", password },
			);
			return response.accessToken;
		} catch (error) {
			lastError = error;
		}
	}

	throw lastError instanceof Error
		? lastError
		: new Error("could not obtain admin access token");
}

export async function verifyIdentityProviderFixtures(): Promise<void> {
	await performCommand({
		host: "r1",
		command: "radtest user user123 192.168.20.30 0 radiussecret",
	})
		.expectOutput([/Access-Accept/])
		.run();

	await performCommand({
		host: "r1",
		command:
			"ldapsearch -x -H ldap://192.168.20.40:389 -b ou=users,dc=raptorgate,dc=local '(uid=user)' uid | grep -q '^uid: user$' && echo ldap-ok",
	})
		.expectOutput([/ldap-ok/])
		.run();
}

export async function ensureProtectedHttpService(): Promise<void> {
	await performCommand({
		host: "h2",
		command: "sudo systemctl restart h2-http",
	})
		.run();

	await performCommand({
		host: "h2",
		command: "systemctl is-active h2-http",
	})
		.expectOutput([/active/])
		.run();
}

export async function clearPortalSession(): Promise<void> {
	await performCommand({
		host: "h1",
		command: `curl -k -sS --max-time 5 -X POST ${PORTAL_API}/logout`,
	})
		.discardError()
		.run();
}

export async function expectH1ToH2Allowed(): Promise<void> {
	await performCommand({
		host: "h1",
		command:
			"curl -sS --connect-timeout 2 --max-time 6 --write-out 'STATUS=%{http_code}\\n' --output /dev/null http://192.168.20.10:8080/",
	})
		.expectOutput([/STATUS=200/])
		.run();
}

export async function expectH1ToH2Blocked(): Promise<void> {
	await performCommand({
		host: "h1",
		command:
			"curl -sS --connect-timeout 2 --max-time 4 http://192.168.20.10:8080/",
	})
		.isErr()
		.run();
}

export async function portalLogin(
	username: string,
	password: string,
): Promise<void> {
	await performCommand({
		host: "h1",
		command: `curl -k -sS --max-time 8 -X POST ${PORTAL_API}/login -H 'content-type: application/json' -d ${shellQuote(JSON.stringify({ username, password }))}`,
	})
		.expectOutput([
			/"sessionId"\s*:/,
			new RegExp(`"username"\\s*:\\s*"${username}"`),
			new RegExp(`"sourceIp"\\s*:\\s*"${H1_SOURCE_IP}"`),
		])
		.run();
}

export async function expectBackendIdentityLoginRejected(
	username: string,
	password: string,
	sourceIp: string,
): Promise<void> {
	await performCommand({
		host: "r1",
		command:
			`curl -k -sS --max-time 8 -X POST ${BACKEND_API}/identity/login ` +
			`-H 'x-raptorgate-portal-ingress: 1' ` +
			`-H 'x-forwarded-for: ${sourceIp}' ` +
			`-H 'content-type: application/json' ` +
			`--write-out '\\nSTATUS=%{http_code}\\n' ` +
			`-d ${shellQuote(JSON.stringify({ username, password }))}`,
	})
		.expectOutput([/STATUS=401/])
		.run();
}

export async function expectNoBackendIdentitySession(
	sourceIp: string,
): Promise<void> {
	await performCommand({
		host: "r1",
		command:
			`curl -k -sS --max-time 8 ${BACKEND_API}/identity/session ` +
			`-H 'x-raptorgate-portal-ingress: 1' ` +
			`-H 'x-forwarded-for: ${sourceIp}'`,
	})
		.expectOutput([/"authenticated"\s*:\s*false/])
		.run();
}

export async function expectPortalSession(
	username: string,
	groupName: string,
): Promise<void> {
	await performCommand({
		host: "h1",
		command: `curl -k -sS --max-time 8 ${PORTAL_API}/session`,
	})
		.expectOutput([
			/"authenticated"\s*:\s*true/,
			new RegExp(`"username"\\s*:\\s*"${username}"`),
			new RegExp(`"groups"\\s*:\\s*\\[[^\\]]*"${groupName}"`),
		])
		.run();
}

export async function portalLogout(): Promise<void> {
	await performCommand({
		host: "h1",
		command: `curl -k -sS --max-time 8 -X POST ${PORTAL_API}/logout`,
	})
		.expectOutput([/"revoked"\s*:\s*true/])
		.run();
}

export async function configureRadiusIdentityEnforcement(): Promise<void> {
	const token = await adminAccessToken();
	const radiusProfile = await upsertRadiusProfile(token);
	const ldapProfile = await upsertLdapProfile(token);
	const authProfile = await upsertAuthenticationProfile(token, {
		name: "test-env-radius-with-ldap-groups",
		description: "test-env RADIUS portal profile with LDAP groups",
		isActive: true,
		provider: "radius",
		radiusProfileId: radiusProfile.id,
		ldapProfileId: ldapProfile.id,
		groupSource: "ldap",
		sessionTtlSeconds: 300,
		adminRoleMappings: [],
	});

	await selectPortalAuthenticationProfile(token, authProfile.id);
	await pushIdentityPolicySnapshot("radius");
	await clearPortalSession();
}

export async function configureLdapIdentityEnforcement(): Promise<void> {
	const token = await adminAccessToken();
	const ldapProfile = await upsertLdapProfile(token);
	const authProfile = await upsertAuthenticationProfile(token, {
		name: "test-env-ldap-portal",
		description: "test-env LDAP portal profile",
		isActive: true,
		provider: "ldap",
		radiusProfileId: null,
		ldapProfileId: ldapProfile.id,
		groupSource: "ldap",
		sessionTtlSeconds: 300,
		adminRoleMappings: [],
	});

	await selectPortalAuthenticationProfile(token, authProfile.id);
	await pushIdentityPolicySnapshot("ldap");
	await clearPortalSession();
}

async function currentIdentityConfig(token: string): Promise<IdentityConfig> {
	return backendJson<IdentityConfig>("GET", "/identity-config", undefined, token);
}

async function upsertSecret(
	token: string,
	type: "radius" | "ldap",
	name: string,
	value: string,
): Promise<string> {
	const path = `/secrets/identity/${type}/${name}`;
	await backendJson("PUT", path, { value }, token);
	return `secret://identity/${type}/${name}`;
}

async function upsertRadiusProfile(token: string): Promise<IdentityProfile> {
	const sharedSecretRef = await upsertSecret(
		token,
		"radius",
		"test-radius-enforcement",
		"radiussecret",
	);
	const body: RadiusProfileInput = {
		name: "test-env-radius-enforcement",
		description: "test-env RADIUS enforcement profile",
		isActive: true,
		host: "192.168.20.30",
		port: 1812,
		sharedSecretRef,
		timeoutMs: 1500,
		retries: 1,
		nasIp: "192.168.20.254",
		nasIdentifier: "raptorgate-test-env",
		calledStationId: "test-env-portal",
	};
	const config = await currentIdentityConfig(token);
	const existing = config.radiusServerProfiles.find(
		(profile) => profile.name === body.name,
	);
	const next = existing
		? await backendJson<IdentityConfig>(
				"PUT",
				`/identity-config/radius-profiles/${existing.id}`,
				body,
				token,
			)
		: await backendJson<IdentityConfig>(
				"POST",
				"/identity-config/radius-profiles",
				body,
				token,
			);

	return requiredProfile(next.radiusServerProfiles, body.name);
}

async function upsertLdapProfile(token: string): Promise<IdentityProfile> {
	const bindPasswordRef = await upsertSecret(
		token,
		"ldap",
		"test-ldap-enforcement",
		"admin",
	);
	const body: LdapProfileInput = {
		name: "test-env-ldap-enforcement",
		description: "test-env LDAP enforcement profile",
		isActive: true,
		host: "192.168.20.40",
		port: 389,
		tlsMode: "disabled",
		bindDn: "cn=admin,dc=raptorgate,dc=local",
		bindPasswordRef,
		userBaseDn: "ou=users,dc=raptorgate,dc=local",
		userFilterAttribute: "uid",
		groupBaseDn: "ou=groups,dc=raptorgate,dc=local",
		groupMemberAttribute: "memberUid",
		groupNameAttribute: "cn",
		timeoutMs: 1500,
		cacheTtlSeconds: 60,
	};
	const config = await currentIdentityConfig(token);
	const existing = config.ldapServerProfiles.find(
		(profile) => profile.name === body.name,
	);
	const next = existing
		? await backendJson<IdentityConfig>(
				"PUT",
				`/identity-config/ldap-profiles/${existing.id}`,
				body,
				token,
			)
		: await backendJson<IdentityConfig>(
				"POST",
				"/identity-config/ldap-profiles",
				body,
				token,
			);

	return requiredProfile(next.ldapServerProfiles, body.name);
}

async function upsertAuthenticationProfile(
	token: string,
	body: AuthProfileInput,
): Promise<IdentityProfile> {
	const config = await currentIdentityConfig(token);
	const existing = config.authenticationProfiles.find(
		(profile) => profile.name === body.name,
	);
	const next = existing
		? await backendJson<IdentityConfig>(
				"PUT",
				`/identity-config/authentication-profiles/${existing.id}`,
				body,
				token,
			)
		: await backendJson<IdentityConfig>(
				"POST",
				"/identity-config/authentication-profiles",
				body,
				token,
			);

	return requiredProfile(next.authenticationProfiles, body.name);
}

async function selectPortalAuthenticationProfile(
	token: string,
	profileId: string,
): Promise<void> {
	await backendJson(
		"PATCH",
		"/identity-config/settings",
		{
			portalAuthenticationProfileId: profileId,
			portalListener: {
				enabled: true,
				interfaceName: "eth1",
				zoneId: null,
				bindAddress: "192.168.10.254",
				bindPort: 443,
			},
		},
		token,
	);
}

async function pushIdentityPolicySnapshot(label: string): Promise<void> {
	const bundle = createDefaultSnapshotBundle({
		rules: [
			{
				id: crypto.randomUUID(),
				name: `identity-${label}-users-only`,
				zonePairId: "00000000-0000-0000-0000-000000000000",
				priority: 0,
				content: `
					match auth_state {
						= authenticated:
							match identity_group {
								= "users":
									match protocol {
										= tcp:
											match dst_port {
												= 8080: verdict allow
												_: verdict drop
											}
										_: verdict drop
									}
								_: verdict drop
							}
						_: verdict drop
					}
				`,
			},
		],
	});

	await request("PushActiveConfigSnapshot", {
		correlationId: crypto.randomUUID(),
		reason: `apply identity ${label} enforcement test policy`,
		snapshot: {
			id: crypto.randomUUID(),
			versionNumber: 1,
			snapshotType: "manual_import",
			checksum: `identity-${label}-enforcement-checksum`,
			isActive: true,
			changesSummary: `identity ${label} enforcement test policy`,
			createdAt: new Date(),
			createdBy: "identity-enforcement-test",
			bundle,
		},
	})
		.expectResponse((response: any) => response?.accepted === true)
		.run();
}

function requiredProfile(
	profiles: IdentityProfile[],
	name: string,
): IdentityProfile {
	const profile = profiles.find((item) => item.name === name);
	if (!profile) throw new Error(`identity profile ${name} was not returned`);
	return profile;
}
