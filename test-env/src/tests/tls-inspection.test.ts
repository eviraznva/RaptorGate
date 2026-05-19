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

function buildPermissiveSnapshot() {
	const defaultRule = DEFAULT_POLICIES[0]!;
	return createDefaultSnapshotBundle({
		rules: [
			{
				...defaultRule,
				id: crypto.randomUUID(),
				name: "tls-inspection-allow-all",
				content: "match ip_ver { =v4: verdict allow }",
				zonePairId: defaultRule.zonePairId,
			},
		],
	});
}

describe("TLS Inspection", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "tls-inspection-permissive-checksum",
				isActive: true,
				changesSummary: "permissive policy for tls inspection test",
				createdAt: new Date(),
				createdBy: "tls-inspection-test",
				bundle: buildPermissiveSnapshot(),
			},
		}).run();
	}, { timeout: 120_000 });

	test("presents a trusted RaptorGate certificate on h2", async () => {
		await performCommand({
			host: "h2",
			command:
				"bash -lc 'set -o pipefail; openssl s_client -verify_return_error -connect www.google.com:443 -servername www.google.com -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer'",
		})
			.expectOutput([
				/subject=CN = www\.google\.com/,
				/issuer=CN = RaptorGate CA, O = RaptorGate/,
			])
			.run();
	}, { timeout: 60_000 });
});
