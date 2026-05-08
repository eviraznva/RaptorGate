import { beforeAll, describe, test } from "bun:test";
import "../harness";
import {
	getClient,
	getSnapshotClient,
	resetFirewallState,
	performCommand,
} from "../harness";
import {
	InterfaceStatus,
} from "../generated/config/config_models";
import {
	createDefaultSnapshotBundle,
	DEFAULT_ZONE_INTERFACES,
} from "../harness/fixtures";

describe("VLAN Declarative Config", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	async function pushVlanConfig(vlanInterfaces: any[]): Promise<void> {
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
						checksum: "test-vlan-declarative",
						isActive: true,
						changesSummary: "vlan declarative config test",
						createdAt: new Date(),
						createdBy: "test-env-vlan",
						bundle: createDefaultSnapshotBundle({
							zoneInterfaces: [
								...DEFAULT_ZONE_INTERFACES,
								...vlanInterfaces,
							],
						}),
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
	}

	test("creates a new VLAN interface", async () => {
		const parentId = DEFAULT_ZONE_INTERFACES[0].id;
		const vlanId = 100;
		const vlanInterface = {
			id: crypto.randomUUID(),
			zoneId: DEFAULT_ZONE_INTERFACES[0].zoneId,
			vlan: { parentInterfaceId: parentId, vlanId },
			sniffed: false,
			status: InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED,
			addresses: [],
		};

		await pushVlanConfig([vlanInterface]);

		await performCommand({
			host: "r1",
			command: `ip -j link show eth1.${vlanId}`,
		})
			.expectOutput([new RegExp(`eth1\\.${vlanId}`)])
			.run();
	});

	test("creates and then removes a VLAN interface", async () => {
		const parentId = DEFAULT_ZONE_INTERFACES[0].id;
		const vlanId = 200;
		const vlanInterface = {
			id: crypto.randomUUID(),
			zoneId: DEFAULT_ZONE_INTERFACES[0].zoneId,
			vlan: { parentInterfaceId: parentId, vlanId },
			sniffed: false,
			status: InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED,
			addresses: [],
		};

		await pushVlanConfig([vlanInterface]);

		await performCommand({
			host: "r1",
			command: `ip -j link show eth1.${vlanId}`,
		})
			.expectOutput([new RegExp(`eth1\\.${vlanId}`)])
			.run();

		await pushVlanConfig([]);

		await performCommand({
			host: "r1",
			command: `ip -j link show eth1.${vlanId}`,
		})
			.isErr()
			.run();
	});

	test("creates 2 VLANs, then removes one via config update", async () => {
		const parentId = DEFAULT_ZONE_INTERFACES[0].id;
		const vlan1Id = 300;
		const vlan2Id = 301;

		const vlan1 = {
			id: crypto.randomUUID(),
			zoneId: DEFAULT_ZONE_INTERFACES[0].zoneId,
			vlan: { parentInterfaceId: parentId, vlanId: vlan1Id },
			sniffed: false,
			status: InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED,
			addresses: [],
		};

		const vlan2 = {
			id: crypto.randomUUID(),
			zoneId: DEFAULT_ZONE_INTERFACES[0].zoneId,
			vlan: { parentInterfaceId: parentId, vlanId: vlan2Id },
			sniffed: false,
			status: InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED,
			addresses: [],
		};

		await pushVlanConfig([vlan1, vlan2]);

		await performCommand({
			host: "r1",
			command: `ip -j link show eth1.${vlan1Id}`,
		})
			.expectOutput([new RegExp(`eth1\\.${vlan1Id}`)])
			.run();

		await performCommand({
			host: "r1",
			command: `ip -j link show eth1.${vlan2Id}`,
		})
			.expectOutput([new RegExp(`eth1\\.${vlan2Id}`)])
			.run();

		await pushVlanConfig([vlan1]);

		await performCommand({
			host: "r1",
			command: `ip -j link show eth1.${vlan1Id}`,
		})
			.expectOutput([new RegExp(`eth1\\.${vlan1Id}`)])
			.run();

		await performCommand({
			host: "r1",
			command: `ip -j link show eth1.${vlan2Id}`,
		})
			.isErr()
			.run();
	});

	test("changes the address of a VLAN interface", async () => {
		const parentId = DEFAULT_ZONE_INTERFACES[0].id;
		const vlanId = 400;
		const address1 = "10.100.0.1/24";
		const address2 = "10.200.0.1/24";

		const vlanInterface = {
			id: crypto.randomUUID(),
			zoneId: DEFAULT_ZONE_INTERFACES[0].zoneId,
			vlan: { parentInterfaceId: parentId, vlanId },
			sniffed: false,
			status: InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED,
			addresses: [address1],
		};

		await pushVlanConfig([vlanInterface]);

		await performCommand({
			host: "r1",
			command: `ip -j addr show eth1.${vlanId}`,
		})
			.expectOutput([/10\.100\.0\.1/])
			.run();

		vlanInterface.addresses = [address2];
		await pushVlanConfig([vlanInterface]);

		await performCommand({
			host: "r1",
			command: `ip -j addr show eth1.${vlanId}`,
		})
			.expectOutput([/10\.200\.0\.1/])
			.run();

		await performCommand({
			host: "r1",
			command: `ip -j addr show eth1.${vlanId}`,
		})
			.expectOutput([/^(?![\s\S]*10\.100\.0\.1)[\s\S]*$/])
			.run();
	});
});
