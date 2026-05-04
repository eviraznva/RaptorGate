import { describe, test, beforeAll } from "bun:test";
import "../harness";
import {
	resetFirewallState,
	getClient,
	getSnapshotClient,
	performCommand,
} from "../harness";
import { createVlanZoneBundle } from "../harness/fixtures";
import { sleep } from "bun";

describe("VLAN Zone Communication", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	test("permissive policy allows all IPv4 traffic between vlan10 and vlan20", async () => {
		const rules = [
			{
				id: crypto.randomUUID(),
				name: "vlan10-to-vlan20-allow-all",
				zonePairId: "",
				priority: 0,
				content: `
					match ip_ver {
						=v4: verdict allow
					}
				`,
			},
			{
				id: crypto.randomUUID(),
				name: "vlan20-to-vlan10-allow-all",
				zonePairId: "",
				priority: 0,
				content: `
					match ip_ver {
						=v4: verdict allow
					}
				`,
			},
		];

		const bundle = createVlanZoneBundle(rules);
		const snapshotClient = getSnapshotClient();

		await new Promise<void>((resolve, reject) => {
			snapshotClient.pushActiveConfigSnapshot(
				{
					correlationId: crypto.randomUUID(),
					reason: "apply",
					snapshot: {
						id: crypto.randomUUID(),
						versionNumber: 1,
						snapshotType: "manual_import",
						checksum: "vlan-permissive-test",
						isActive: true,
						changesSummary: "vlan permissive policy test",
						createdAt: new Date(),
						createdBy: "test-env-vlan",
						bundle,
					},
				},
				(err: Error | null, resp: any) => {
					if (err) {
						reject(err);
						return;
					}
					if (!resp?.accepted) {
						reject(
							new Error(resp?.message || "snapshot push rejected"),
						);
						return;
					}
					resolve();
				},
			);
		});

		await sleep(500);

		await performCommand({
			host: "hvlan10",
			command: "ping -c 1 -W 2 192.168.120.50",
		})
			.expectOutput([/1 packets transmitted, 1 received/])
			.isOk()
			.run();

		await performCommand({
			host: "hvlan20",
			command: "ping -c 1 -W 2 192.168.110.50",
		})
			.expectOutput([/1 packets transmitted, 1 received/])
			.isOk()
			.run();

		const ncServer = await performCommand({
			host: "hvlan20",
			command: "nc -l 4444",
		}).runDetached();

		try {
			await performCommand({
				host: "hvlan10",
				command: 'echo "test" | nc -w 2 192.168.120.50 4444',
			})
				.isOk()
				.run();
		} finally {
			await ncServer.kill();
		}

		const ncServerReverse = await performCommand({
			host: "hvlan10",
			command: "nc -l 4445",
		}).runDetached();

		try {
			await performCommand({
				host: "hvlan20",
				command: 'echo "test" | nc -w 2 192.168.110.50 4445',
			})
				.isOk()
				.run();
		} finally {
			await ncServerReverse.kill();
		}
	});

	test("restrictive policy blocks ICMP but allows TCP between vlan10 and vlan20", async () => {
		const rules = [
			{
				id: crypto.randomUUID(),
				name: "vlan10-to-vlan20-restrictive",
				zonePairId: "",
				priority: 0,
				content: `
					match protocol {
						=icmp: verdict drop
						=tcp: verdict allow
					}
				`,
			},
			{
				id: crypto.randomUUID(),
				name: "vlan20-to-vlan10-restrictive",
				zonePairId: "",
				priority: 0,
				content: `
					match protocol {
						=icmp: verdict drop
						=tcp: verdict allow
					}
				`,
			},
		];

		const bundle = createVlanZoneBundle(rules);
		const snapshotClient = getSnapshotClient();

		await new Promise<void>((resolve, reject) => {
			snapshotClient.pushActiveConfigSnapshot(
				{
					correlationId: crypto.randomUUID(),
					reason: "apply",
					snapshot: {
						id: crypto.randomUUID(),
						versionNumber: 1,
						snapshotType: "manual_import",
						checksum: "vlan-restrictive-test",
						isActive: true,
						changesSummary: "vlan restrictive policy test",
						createdAt: new Date(),
						createdBy: "test-env-vlan",
						bundle,
					},
				},
				(err: Error | null, resp: any) => {
					if (err) {
						reject(err);
						return;
					}
					if (!resp?.accepted) {
						reject(
							new Error(resp?.message || "snapshot push rejected"),
						);
						return;
					}
					resolve();
				},
			);
		});

		await sleep(500);

		await performCommand({
			host: "hvlan10",
			command: "ping -c 1 -W 2 192.168.120.50",
		})
			.isErr()
			.run();

		await performCommand({
			host: "hvlan20",
			command: "ping -c 1 -W 2 192.168.110.50",
		})
			.isErr()
			.run();

		const ncServer = await performCommand({
			host: "hvlan20",
			command: "nc -l 4444",
		}).runDetached();

		try {
			await performCommand({
				host: "hvlan10",
				command: 'echo "test" | nc -w 2 192.168.120.50 4444',
			})
				.isOk()
				.run();
		} finally {
			await ncServer.kill();
		}

		const ncServerReverse = await performCommand({
			host: "hvlan10",
			command: "nc -l 4445",
		}).runDetached();

		try {
			await performCommand({
				host: "hvlan20",
				command: 'echo "test" | nc -w 2 192.168.110.50 4445',
			})
				.isOk()
				.run();
		} finally {
			await ncServerReverse.kill();
		}
	});
});
