import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import path from "node:path";
import { DefaultPolicy } from "../generated/common/common";
import { performCommand, request } from "../harness";
import { createDefaultSnapshotBundle, DEFAULT_ZONES } from "../harness/fixtures";

const PROTO_ROOT = path.resolve(__dirname, "../../../proto");
const QUERY_LOCAL_PORT = 50051;
const H1_SOURCE_IP = "192.168.10.10";
const LDAP_BASE_DN = "dc=raptorgate,dc=local";
const LDAP_USERS_DN = `ou=users,${LDAP_BASE_DN}`;
const LDAP_GROUPS_DN = `ou=groups,${LDAP_BASE_DN}`;

const identityProto = grpc.loadPackageDefinition(
	protoLoader.loadSync(
		[path.join(PROTO_ROOT, "services", "identity_session_service.proto")],
		{
			keepCase: false,
			longs: String,
			enums: String,
			defaults: true,
			oneofs: true,
			includeDirs: [PROTO_ROOT],
		},
	),
) as any;

type IdentitySessionServiceClient = grpc.Client & {
	upsertIdentitySession(
		request: unknown,
		callback: (err: grpc.ServiceError | null, response: unknown) => void,
	): void;
	revokeIdentitySession(
		request: unknown,
		callback: (err: grpc.ServiceError | null, response: { removed?: boolean }) => void,
	): void;
};

function identitySessionClient(): IdentitySessionServiceClient {
	return new identityProto.raptorgate.services.IdentitySessionService(
		`localhost:${QUERY_LOCAL_PORT}`,
		grpc.credentials.createInsecure(),
	) as IdentitySessionServiceClient;
}

function timestamp(secondsFromNow: number): { seconds: string; nanos: number } {
	return {
		seconds: String(Math.floor(Date.now() / 1000) + secondsFromNow),
		nanos: 0,
	};
}

export async function verifyIdentityProviderFixtures(): Promise<void> {
	await assertRadiusAccepts("user", "user123");
	await assertRadiusRejects("user", "wrong-password");
	await assertLdapAccepts("user", "user123");
	await assertLdapRejects("user", "wrong-password");
	await assertLdapGroup("user", "users");
	await assertLdapGroup("guest", "guests");
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

export async function applyIdentityPolicy(label: string): Promise<void> {
	const clientZoneId = crypto.randomUUID();
	const serverZoneId = crypto.randomUUID();
	const clientToServerZonePairId = crypto.randomUUID();
	const serverToClientZonePairId = crypto.randomUUID();

	const bundle = createDefaultSnapshotBundle({
		zones: [
			...DEFAULT_ZONES.map((zone) => ({ ...zone })),
			{ id: clientZoneId, name: `identity-${label}-client` },
			{ id: serverZoneId, name: `identity-${label}-server` },
		],
		zoneInterfaces: [
			{
				id: crypto.randomUUID(),
				zoneId: clientZoneId,
				physical: { interfaceName: "eth1" },
				sniffed: true,
				status: 0,
				addresses: [],
			},
			{
				id: crypto.randomUUID(),
				zoneId: serverZoneId,
				physical: { interfaceName: "eth2" },
				sniffed: true,
				status: 0,
				addresses: [],
			},
		] as any,
		zonePairs: [
			{
				id: clientToServerZonePairId,
				srcZoneId: clientZoneId,
				dstZoneId: serverZoneId,
				defaultPolicy: DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED,
			},
			{
				id: serverToClientZonePairId,
				srcZoneId: serverZoneId,
				dstZoneId: clientZoneId,
				defaultPolicy: DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED,
			},
		],
		rules: [
			{
				id: crypto.randomUUID(),
				name: `identity-${label}-users-only`,
				zonePairId: clientToServerZonePairId,
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
			{
				id: crypto.randomUUID(),
				name: `identity-${label}-server-replies`,
				zonePairId: serverToClientZonePairId,
				priority: 0,
				content: `
					match protocol {
						= tcp:
							match src_port {
								= 8080: verdict allow
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

	await new Promise((resolve) => setTimeout(resolve, 500));
}

export async function assertRadiusAccepts(
	username: string,
	password: string,
): Promise<void> {
	await performCommand({
		host: "r1",
		command: `radtest ${username} ${password} 192.168.20.30 0 radiussecret`,
	})
		.expectOutput([/Access-Accept/])
		.run();
}

export async function assertRadiusRejects(
	username: string,
	password: string,
): Promise<void> {
	await performCommand({
		host: "r1",
		command: `radtest ${username} ${password} 192.168.20.30 0 radiussecret 2>&1 || true`,
	})
		.expectOutput([/Access-Reject/])
		.run();
}

export async function assertLdapAccepts(
	username: string,
	password: string,
): Promise<void> {
	await performCommand({
		host: "r1",
		command:
			`ldapwhoami -x -H ldap://192.168.20.40:389 ` +
			`-D 'uid=${username},${LDAP_USERS_DN}' -w '${password}'`,
	})
		.expectOutput([new RegExp(`dn:uid=${username},${LDAP_USERS_DN}`)])
		.run();
}

export async function assertLdapRejects(
	username: string,
	password: string,
): Promise<void> {
	await performCommand({
		host: "r1",
		command:
			`ldapwhoami -x -H ldap://192.168.20.40:389 ` +
			`-D 'uid=${username},${LDAP_USERS_DN}' -w '${password}' 2>&1 || true`,
	})
		.expectOutput([/Invalid credentials|ldap_bind/])
		.run();
}

export async function assertLdapGroup(
	username: string,
	groupName: string,
): Promise<void> {
	await performCommand({
		host: "r1",
		command:
			`ldapsearch -x -H ldap://192.168.20.40:389 -b ${LDAP_GROUPS_DN} ` +
			`'(memberUid=${username})' cn | grep -q '^cn: ${groupName}$' && echo ldap-group-ok`,
	})
		.expectOutput([/ldap-group-ok/])
		.run();
}

export async function upsertIdentitySession(
	username: string,
	groups: string[],
): Promise<void> {
	const client = identitySessionClient();
	const now = timestamp(0);
	const expiresAt = timestamp(300);

	await new Promise<void>((resolve, reject) => {
		client.upsertIdentitySession(
			{
				session: {
					id: crypto.randomUUID(),
					identityUserId: `test-env-${username}`,
					radiusUsername: username,
					macAddress: "00:00:00:00:00:00",
					ipAddress: H1_SOURCE_IP,
					nasIp: "192.168.20.254",
					calledStationId: "test-env",
					authenticatedAt: now,
					expiresAt,
					groups,
				},
			},
			(err) => {
				if (err) reject(err);
				else resolve();
			},
		);
	});
}

export async function revokeIdentitySession(): Promise<void> {
	const client = identitySessionClient();

	await new Promise<void>((resolve, reject) => {
		client.revokeIdentitySession(
			{ ipAddress: H1_SOURCE_IP },
			(err) => {
				if (err) reject(err);
				else resolve();
			},
		);
	});
}

export async function expectH1ToH2Allowed(): Promise<void> {
	await performCommand({
		host: "h1",
		command:
			"curl -sS --connect-timeout 2 --max-time 6 --write-out 'STATUS=%{http_code}\\n' --output /dev/null http://192.168.20.10:8080/api/ping",
	})
		.expectOutput([/STATUS=200/])
		.run();
}

export async function expectH1ToH2Blocked(): Promise<void> {
	await performCommand({
		host: "h1",
		command:
			"curl -sS --connect-timeout 2 --max-time 4 http://192.168.20.10:8080/api/ping",
	})
		.isErr()
		.run();
}
