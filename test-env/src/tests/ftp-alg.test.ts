import { describe, test, beforeAll } from "bun:test";
import "../harness";
import {
	request,
	performCommand,
	resetFirewallState,
	getClient,
	getSnapshotClient,
} from "../harness";
import {
	createDefaultSnapshotBundle,
	DEFAULT_POLICIES,
} from "../harness/fixtures";

const FTP_SERVER = "192.168.20.10";
const FTP_TEST_FILE = "raptorgate-ftp-test.txt";

function buildPermissiveSnapshot() {
	const defaultRule = DEFAULT_POLICIES[0]!;
	return createDefaultSnapshotBundle({
		rules: [
			{
				...defaultRule,
				id: crypto.randomUUID(),
				name: "allow-all-ipv4",
				content: "match ip_ver { =v4: verdict allow }",
				zonePairId: defaultRule.zonePairId,
			},
		],
	});
}

async function pushPermissive(): Promise<void> {
	await request("PushActiveConfigSnapshot", {
		correlationId: crypto.randomUUID(),
		reason: "apply",
		snapshot: {
			id: crypto.randomUUID(),
			versionNumber: 1,
			snapshotType: "manual_import",
			checksum: `ftp-alg-${crypto.randomUUID()}`,
			isActive: true,
			changesSummary: "permissive policy for ftp alg test",
			createdAt: new Date(),
			createdBy: "ftp-alg-test",
			bundle: buildPermissiveSnapshot(),
		},
	}).run();
}

function activeFtp(command: string): string {
	return (
		`lftp -e 'set ftp:passive-mode off; set net:timeout 8; ` +
		`set net:max-retries 1; set net:reconnect-interval-base 1; ` +
		`${command}; bye' ftp://${FTP_SERVER}`
	);
}

describe("FTP ALG", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	test(
		"active-mode retrieval crosses the ALG-tracked data channel",
		async () => {
			await pushPermissive();

			await performCommand({
				host: "h1",
				command: activeFtp(`cat /${FTP_TEST_FILE}`),
			})
				.expectOutput([/RaptorGate FTP ALG test payload/])
				.run();
		},
		{ timeout: 60000 },
	);

	test(
		"active-mode listing succeeds through the firewall",
		async () => {
			await pushPermissive();

			await performCommand({
				host: "h1",
				command: activeFtp("ls"),
			})
				.expectOutput([new RegExp(FTP_TEST_FILE)])
				.run();
		},
		{ timeout: 60000 },
	);
});
