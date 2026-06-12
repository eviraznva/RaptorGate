import { beforeAll, describe, test } from "bun:test";
import "../harness";
import {
	getClient,
	getSnapshotClient,
	request,
	resetFirewallState,
} from "../harness";
import { performSshPolicyCommand } from "../ssh-helper";
import {
	createSnapshotBundleWithSshMatchers,
	DEFAULT_POLICIES,
	DEFAULT_ZONE_PAIRS,
	denySshMatchers,
	permissiveSshMatchers,
	pushSnapshotWithSshMatchers,
	type SshMatcherField,
} from "../harness/fixtures";
import {
	SshMatchAction,
	type SshMatchers,
	type Rule,
} from "../generated/config/config_models";
import { P } from "ts-pattern";

const SSH_HOSTNAME_CMD =
	"ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null vagrant@192.168.20.10 hostname";

const NEGOTIATED_KEX = "sntrup761x25519-sha512@openssh.com";
const NEGOTIATED_CIPHER = "chacha20-poly1305@openssh.com";
const HOST_KEY_ALG = "ssh-ed25519";

const POLICY_TEST_TIMEOUT = 60_000;

function sshHostname() {
	return performSshPolicyCommand("h1", SSH_HOSTNAME_CMD);
}

function allowMatch(regex: string) {
	return {
		regex,
		onMatch: SshMatchAction.SSH_MATCH_ACTION_ALLOW,
	};
}

function denyMatch(regex: string) {
	return {
		regex,
		onMatch: SshMatchAction.SSH_MATCH_ACTION_DENY,
	};
}

async function pushMatchers(matchers: SshMatchers, rules?: Rule[]) {
	await pushSnapshotWithSshMatchers(getSnapshotClient(), matchers, rules);
}

async function denyThenAllow(
	field: SshMatcherField,
	denyRegex: string,
	allowRegex: string,
) {
	await pushMatchers(denySshMatchers(field, denyRegex));
	await sshHostname().isErr().run();

	const allow = permissiveSshMatchers();
	allow[field] = [allowMatch(allowRegex)];
	await pushMatchers(allow);
	await sshHostname().isOk().expectOutput([/^h2$/]).run();
}

describe("SSH", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	test("h1 can start an ssh session to h2", async () => {
		await sshHostname().expectOutput([/^h2$/]).run();
	});

	describe("policy", () => {
		beforeAll(async () => {
			await resetFirewallState(getClient(), getSnapshotClient());
		});

		test(
			"permissive matchers allow ssh",
			async () => {
				await pushMatchers(permissiveSshMatchers());
				await sshHostname().isOk().expectOutput([/^h2$/]).run();
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"client_software deny then allow",
			async () => {
				await denyThenAllow("clientSoftware", "OpenSSH.*", "OpenSSH.*");
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"server_software deny then allow",
			async () => {
				await denyThenAllow("serverSoftware", "OpenSSH.*", "OpenSSH.*");
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"client_proto_version deny then allow",
			async () => {
				await denyThenAllow("clientProtoVersion", "2\\.0", "2\\.0");
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"server_proto_version deny then allow",
			async () => {
				await denyThenAllow("serverProtoVersion", "2\\.0", "2\\.0");
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"kex deny then allow",
			async () => {
				await denyThenAllow("kex", NEGOTIATED_KEX, NEGOTIATED_KEX);
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"cipher deny then allow",
			async () => {
				await denyThenAllow(
					"cipher",
					"chacha20-poly1305@openssh\\.com",
					"chacha20-poly1305@openssh\\.com",
				);
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"compression deny then allow",
			async () => {
				await denyThenAllow("compression", "none", "none");
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"host_key_alg deny then allow",
			async () => {
				await denyThenAllow("hostKeyAlg", HOST_KEY_ALG, HOST_KEY_ALG);
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"host_key_type deny then allow",
			async () => {
				await denyThenAllow("hostKeyType", HOST_KEY_ALG, HOST_KEY_ALG);
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"mixed fields all allowed succeeds, one deny fails",
			async () => {
				const allowed = permissiveSshMatchers();
				allowed.serverSoftware = [allowMatch("OpenSSH.*")];
				allowed.kex = [allowMatch(NEGOTIATED_KEX)];
				allowed.cipher = [
					allowMatch("chacha20-poly1305@openssh\\.com"),
				];
				await pushMatchers(allowed);
				await sshHostname().isOk().expectOutput([/^h2$/]).run();

				allowed.kex = [denyMatch(NEGOTIATED_KEX)];
				await pushMatchers(allowed);
				await sshHostname().isErr().run();
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"deny wins over allow in same field",
			async () => {
				const matchers = permissiveSshMatchers();
				matchers.cipher = [
					allowMatch(".*"),
					denyMatch("chacha20-poly1305@openssh\\.com"),
				];
				await pushMatchers(matchers);
				await sshHostname().isErr().run();
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"multiple policies all must allow",
			async () => {
				const zonePairId = DEFAULT_ZONE_PAIRS[0]!.id;
				const base = DEFAULT_POLICIES[0]!;
				const allowKex = permissiveSshMatchers();
				allowKex.kex = [allowMatch(NEGOTIATED_KEX)];
				const allowCipher = permissiveSshMatchers();
				allowCipher.cipher = [
					allowMatch("chacha20-poly1305@openssh\\.com"),
				];
				const rules: Rule[] = [
					{
						...base,
						id: crypto.randomUUID(),
						name: "ssh-policy-kex",
						zonePairId,
						priority: 0,
						sshMatchers: allowKex,
					},
					{
						...base,
						id: crypto.randomUUID(),
						name: "ssh-policy-cipher",
						zonePairId,
						priority: 1,
						sshMatchers: allowCipher,
					},
				];
				await pushMatchers(permissiveSshMatchers(), rules);
				await sshHostname().isOk().expectOutput([/^h2$/]).run();

				allowCipher.cipher = [
					denyMatch("chacha20-poly1305@openssh\\.com"),
				];
				rules[1] = { ...rules[1]!, sshMatchers: allowCipher };
				await pushMatchers(permissiveSshMatchers(), rules);
				await sshHostname().isErr().run();
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"default deny client_software blocks ssh",
			async () => {
				await pushMatchers(denySshMatchers("clientSoftware", ".*"));
				await sshHostname().isErr().run();
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);

		test(
			"get policies returns pushed ssh matchers",
			async () => {
				const ruleName = `ssh-policy-roundtrip-${Date.now()}`;
				const matchers = denySshMatchers("kex", NEGOTIATED_KEX);
				const defaultRule = DEFAULT_POLICIES[0]!;
				const bundle = createSnapshotBundleWithSshMatchers(matchers, [
					{
						...defaultRule,
						id: crypto.randomUUID(),
						name: ruleName,
						zonePairId: DEFAULT_ZONE_PAIRS[0]!.id,
						sshMatchers: matchers,
					},
				]);

				await request("PushActiveConfigSnapshot", {
					correlationId: crypto.randomUUID(),
					reason: "apply",
					snapshot: {
						id: crypto.randomUUID(),
						versionNumber: 1,
						snapshotType: "manual_import",
						checksum: "ssh-policy-roundtrip-checksum",
						isActive: true,
						changesSummary: "ssh policy roundtrip",
						createdAt: new Date(),
						createdBy: "ssh-policy-test",
						bundle,
					},
				}).run();

				await request("GetPolicies", {})
					.expectResponse(
						P.when((res: any) =>
							res?.rules?.some(
								(r: any) =>
									r.name === ruleName &&
									r.sshMatchers?.kex?.some(
										(m: any) =>
											m.regex === NEGOTIATED_KEX &&
											(m.onMatch ===
												SshMatchAction.SSH_MATCH_ACTION_DENY ||
												m.onMatch === "SSH_MATCH_ACTION_DENY"),
									),
							),
						),
					)
					.run();
			},
			{ timeout: POLICY_TEST_TIMEOUT },
		);
	});
});
