import { describe, test, beforeAll } from "bun:test";
import "../harness";
import {
	request,
	resetFirewallState,
	getClient,
	getSnapshotClient,
	performCommand,
} from "../harness";
import { DefaultPolicy } from "../generated/common/common";
import type { ZoneInterface } from "../generated/config/config_models";
import {
	createDefaultSnapshotBundle,
	DEFAULT_APP_CONFIG,
	DEFAULT_ZONE_INTERFACES,
	DEFAULT_ZONES,
} from "../harness/fixtures";
import { sleep } from "bun";

describe("Zone Policy E2E", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	test("ICMP allow_warn, TCP/UDP drop_warn between zone1 and zone2", async () => {
		const zone1Id = crypto.randomUUID();
		const zone2Id = crypto.randomUUID();
		const zonePair1to2Id = crypto.randomUUID();
		const zonePair2to1Id = crypto.randomUUID();
		const zi1Id = crypto.randomUUID();
		const zi2Id = crypto.randomUUID();

		const bundle = createDefaultSnapshotBundle({
			zones: [
				{
					id: "00000000-0000-0000-0000-000000000000",
					name: "default",
				},
				{ id: zone1Id, name: "zone1" },
				{ id: zone2Id, name: "zone2" },
			],
			zoneInterfaces: [
				{
					id: zi1Id,
					zoneId: zone1Id,
					physical: { interfaceName: "eth1" },
					sniffed: true,
					status: 0,
					addresses: [],
				},
				{
					id: zi2Id,
					zoneId: zone2Id,
					physical: { interfaceName: "eth2" },
					sniffed: true,
					status: 0,
					addresses: [],
				},
			] as any,
			zonePairs: [
				{
					id: zonePair1to2Id,
					srcZoneId: zone1Id,
					dstZoneId: zone2Id,
					defaultPolicy: DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED,
				},
				{
					id: zonePair2to1Id,
					srcZoneId: zone2Id,
					dstZoneId: zone1Id,
					defaultPolicy: DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED,
				},
			],
			rules: [
				{
					id: crypto.randomUUID(),
					name: "zone1-to-zone2-policy",
					zonePairId: zonePair1to2Id,
					priority: 0,
					content: `
            match protocol {
              =icmp: verdict allow_warn "icmp allowed"
              =tcp: verdict drop_warn "tcp dropped"
              =udp: verdict drop_warn "udp dropped"
            }
          `,
				},
				{
					id: crypto.randomUUID(),
					name: "zone2-to-zone1-policy",
					zonePairId: zonePair2to1Id,
					priority: 0,
					content: `
            match protocol {
              =icmp: verdict allow_warn "icmp allowed"
              =tcp: verdict drop_warn "tcp dropped"
              =udp: verdict drop_warn "udp dropped"
            }
          `,
				},
			],
		});

		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply e2e zone policy",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "zone-policy-e2e-checksum",
				isActive: true,
				changesSummary: "zone-based policy for e2e test",
				createdAt: new Date(),
				createdBy: "test-env",
				bundle,
			},
		})
			.expectResponse((response: any) => {
				console.log(response);
				return true;
			})
			.run();

		await sleep(500);

		// ICMP should be allowed with warning
		await performCommand({
			host: "h1",
			command: "ping -c 1 -W 1 192.168.20.10",
		})
			.expectEvents([
				{
					kind: "policyWarning",
					match: { message: "icmp allowed", verdict: "allow" },
				},
			])
			.expectOutput([/1 packets transmitted, 1 received/])
			.isOk()
			.run();

		// TCP should be dropped with warning
		const ncatServer = await performCommand({
			host: "h2",
			command: "ncat -l 4444",
		}).runDetached();

		try {
			await performCommand({
				host: "h1",
				command: "ncat -w 1 192.168.20.10 4444",
			})
				.expectEvents([
					{
						kind: "policyWarning",
						match: { message: "tcp dropped", verdict: "drop" },
					},
				])
				.isErr()
				.run();
		} finally {
			await ncatServer.kill();
		}

		// UDP should be dropped with warning
		const udpServer = await performCommand({
			host: "h2",
			command: "timeout 3 nc -u -l 5555",
		}).runDetached();

		try {
			await performCommand({
				host: "h1",
				command: 'echo "test" | nc -u -w 1 192.168.20.10 5555',
			})
				.expectEvents([
					{
						kind: "policyWarning",
						match: { message: "udp dropped", verdict: "drop" },
					},
				])
				.run();
		} finally {
			await udpServer.kill();
		}
	}, {timeout: 10_000} );
});
