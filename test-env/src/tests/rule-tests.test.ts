import { describe, test, beforeAll, beforeEach, afterEach } from "bun:test";
import "../harness";
import {
	request,
	resetFirewallState,
	getClient,
	getSnapshotClient,
	performCommand,
} from "../harness";
import { createDefaultSnapshotBundle } from "../harness/fixtures";
import { sleep } from "bun";

async function cleanupRuleListeners() {
	await performCommand({
		host: "h1",
		command: "pkill -f '[n]cat -l 1234[56]' || true",
	})
		.discardError()
		.run();
	await sleep(200);
}

describe("Rule Tests", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});
	beforeEach(cleanupRuleListeners);
	afterEach(cleanupRuleListeners);

	test("blocks dst_port 12345 and allows dst_port 12346", async () => {
		const bundle = createDefaultSnapshotBundle({
			rules: [
				{
					id: crypto.randomUUID(),
					name: "dst-port-filter",
					zonePairId: "00000000-0000-0000-0000-000000000000",
					priority: 0,
					content: `match dst_port { 
						=12345: verdict drop 
						_: verdict allow 
					}`,
				},
			],
		});

		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply dst_port filtering rule",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "dst-port-rule-checksum",
				isActive: true,
				changesSummary: "dst_port filtering test",
				createdAt: new Date(),
				createdBy: "rule-tests",
				bundle,
			},
		})
			.expectResponse((response: any) => response?.accepted === true)
			.run();

		await new Promise((resolve) => setTimeout(resolve, 500));

		const server12346 = await performCommand({
			host: "h1",
			command: "timeout 10 ncat -l 12346 >/dev/null",
		}).runDetached();

		await sleep(500);

		try {
			await performCommand({
				host: "h2",
				command: "echo test | ncat -w 2 192.168.10.10 12346",
			})
				.isOk()
				.run();
		} finally {
			await server12346.kill();
		}

		const server12345 = await performCommand({
			host: "h1",
			command: "timeout 10 ncat -l 12345 >/dev/null",
		}).runDetached();

		await sleep(200);

		try {
			await performCommand({
				host: "h2",
				command: "echo test | ncat -w 2 192.168.10.10 12345",
			})
				.isErr()
				.run();
		} finally {
			await server12345.kill();
		}
	}, { timeout: 20_000 });
});
