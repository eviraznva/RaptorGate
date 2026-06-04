import { describe, test, beforeAll } from "bun:test";
import { sleep } from "bun";
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

describe("Session Teardown", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	// test("allows reusing a completed TCP tuple with a permissive policy", async () => {
	// 	const defaultRule = DEFAULT_POLICIES[0]!;
	//
	// 	await request("PushActiveConfigSnapshot", {
	// 		correlationId: crypto.randomUUID(),
	// 		reason: "apply",
	// 		snapshot: {
	// 			id: crypto.randomUUID(),
	// 			versionNumber: 1,
	// 			snapshotType: "manual_import",
	// 			checksum: "session-teardown-permissive-checksum",
	// 			isActive: true,
	// 			changesSummary: "permissive policy for session teardown test",
	// 			createdAt: new Date(),
	// 			createdBy: "session-teardown-test",
	// 			bundle: createDefaultSnapshotBundle({
	// 				rules: [
	// 					{
	// 						...defaultRule,
	// 						id: crypto.randomUUID(),
	// 						name: "session-teardown-allow-all-ipv4",
	// 						content: "match ip_ver { =v4: verdict allow }",
	// 						zonePairId: defaultRule.zonePairId,
	// 					},
	// 				],
	// 			}),
	// 		},
	// 	}).run();
	//
	// 	await performCommand({
	// 		host: "h2",
	// 		command: "pkill -f 'nc -l 12345'",
	// 	})
	// 		.discardError()
	// 		.run();
	//
	// 	const server = await performCommand({
	// 		host: "h2",
	// 		command:
	// 			"rm -f /tmp/raptorgate-session-teardown.out; sh -c 'for i in 1 2; do nc -l 12345 >> /tmp/raptorgate-session-teardown.out; done'",
	// 	}).runDetached();
	//
	// 	try {
	// 		for (let attempt = 0; attempt < 2; attempt++) {
	// 			await performCommand({
	// 				host: "h1",
	// 				command:
	// 					"echo 'hello' | nc -p 12346 192.168.20.10 12345",
	// 			}).run();
	// 		}
	//
	// 		await sleep(500);
	//
	// 		await performCommand({
	// 			host: "h2",
	// 			command: "grep -c '^hello$' /tmp/raptorgate-session-teardown.out",
	// 		})
	// 			.expectOutput([/^2$/])
	// 			.run();
	// 	} finally {
	// 		await server.kill();
	// 	}
	// }, { timeout: 20_000 });
});
