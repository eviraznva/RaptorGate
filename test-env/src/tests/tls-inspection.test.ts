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
	DEFAULT_APP_CONFIG,
	DEFAULT_POLICIES,
} from "../harness/fixtures";
import { DecryptionFailureAction } from "../generated/config/config_models";

function buildTlsInspectionSnapshot(
	decryptionMirror?: {
		enabled: boolean;
		targetHost: string;
		targetPort: number;
		includeClientToServer: boolean;
		includeServerToClient: boolean;
		forwardedOnly: boolean;
		maxSessionBytes: number;
	},
) {
	const defaultRule = DEFAULT_POLICIES[0]!;
	return createDefaultSnapshotBundle({
		appConfig: {
			...DEFAULT_APP_CONFIG,
			pkiDir: "/var/lib/raptorgate/pki",
			sslInspectionEnabled: true,
			tlsInspectionPorts: [443],
		},
		tlsInspectionPolicy: {
			blockEchNoSni: false,
			blockAllEch: false,
			stripEchDns: false,
			logEchAttempts: false,
			knownPinnedDomains: [],
			decryptionExclusions: [],
			decryptionFailureCache: {
				version: 1,
				enabled: true,
				failureThreshold: 3,
				failureWindowSec: 60,
				localExclusionTtlSec: 86400,
				maxEntries: 4096,
				action: DecryptionFailureAction.DECRYPTION_FAILURE_ACTION_CACHE_AND_BYPASS,
			},
			decryptionMirror,
		},
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

function httpsRequestCommand(host: string) {
	return `timeout 25 bash -lc 'set -o pipefail; printf "GET / HTTP/1.1\\r\\nHost: ${host}\\r\\nConnection: close\\r\\n\\r\\n" | openssl s_client -connect ${host}:443 -servername ${host} -quiet 2>&1'`;
}

async function waitForSnapshotSettle(): Promise<void> {
	await new Promise((resolve) => setTimeout(resolve, 750));
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
				bundle: buildTlsInspectionSnapshot(),
			},
		}).run();
		await waitForSnapshotSettle();
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

	test("completes an intercepted HTTPS request through the L4 pipeline", async () => {
		await performCommand({
			host: "h2",
			command: httpsRequestCommand("www.google.com"),
		})
			.expectOutput([
				/depth=1 CN = RaptorGate CA, O = RaptorGate/,
				/HTTP\/1\.1 200 OK/,
			])
			.run();
	}, { timeout: 60_000 });

	test("mirrors decrypted client plaintext", async () => {
		await request("PushActiveConfigSnapshot", {
			correlationId: crypto.randomUUID(),
			reason: "apply",
			snapshot: {
				id: crypto.randomUUID(),
				versionNumber: 1,
				snapshotType: "manual_import",
				checksum: "tls-inspection-mirror-checksum",
				isActive: true,
				changesSummary: "enable decrypted traffic mirror for tls inspection test",
				createdAt: new Date(),
				createdBy: "tls-inspection-test",
				bundle: buildTlsInspectionSnapshot({
					enabled: true,
					targetHost: "127.0.0.1",
					targetPort: 9000,
					includeClientToServer: true,
					includeServerToClient: false,
					forwardedOnly: true,
					maxSessionBytes: 65536,
				}),
			},
		}).run();
		await waitForSnapshotSettle();

		await performCommand({
			host: "r1",
			command:
				"bash -lc 'pkill -f \"nc -lk 127.0.0.1 9000\" 2>/dev/null || true; rm -f /tmp/rg_tls_mirror.bin'",
		})
			.discardError()
			.run();

		const mirror = await performCommand({
			host: "r1",
			command:
				"bash -lc 'timeout 30 nc -lk 127.0.0.1 9000 > /tmp/rg_tls_mirror.bin'",
		}).runDetached();
		mirror.defer_cleanup();

		try {
			await performCommand({
				host: "h2",
				command: httpsRequestCommand("www.google.com"),
			})
				.expectOutput([/HTTP\/1\.1 200 OK/])
				.run();

			await new Promise((resolve) => setTimeout(resolve, 1000));
			await mirror.kill();
			await mirror.handle.waitForExit();

			await performCommand({
				host: "r1",
				command:
					"bash -lc 'grep -a -q \"GET / HTTP/1.1\" /tmp/rg_tls_mirror.bin && grep -a -q \"Host: www.google.com\" /tmp/rg_tls_mirror.bin && echo mirror-ok'",
			})
				.expectOutput([/mirror-ok/])
				.run();
		} finally {
			await mirror.kill();
		}
	}, { timeout: 90_000 });
});
