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

const PROBE_TARGET = "192.168.10.10"; // h1
const PROBE_GATEWAY = "192.168.20.254"; // r1 (eth2 / subnet2 side)

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
			checksum: `ml-alert-${crypto.randomUUID()}`,
			isActive: true,
			changesSummary: "permissive policy for ml alert test",
			createdAt: new Date(),
			createdBy: "ml-alert-test",
			bundle: buildPermissiveSnapshot(),
		},
	}).run();
}

function probeCommand(durationSeconds: number): string {
	return (
		`sudo raptorgate-ml-traffic --target ${PROBE_TARGET} ` +
		`--gateway ${PROBE_GATEWAY} --interface eth1 ` +
		`--duration ${durationSeconds} --rate 200 --mode mixed`
	);
}

describe("ML Anomaly Alert", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	test(
		"attack-like probe traffic raises mlThreatDetected on the V2 session path",
		async () => {
			await pushPermissive();

			await performCommand({
				host: "h2",
				command: probeCommand(20),
			})
				.expectEvents([{ kind: "mlThreatDetected" }])
				.run();
		},
		{ timeout: 90000 },
	);

	test(
		"ml threat event carries scored attack metadata",
		async () => {
			await pushPermissive();

			await performCommand({
				host: "h2",
				command: probeCommand(20),
			})
				.expectEvents([
					{
						kind: "mlThreatDetected",
						match: {
							srcIp: "192.168.20.10",
							transportProtocol: "tcp",
						},
					},
				])
				.run();
		},
		{ timeout: 90000 },
	);
});
