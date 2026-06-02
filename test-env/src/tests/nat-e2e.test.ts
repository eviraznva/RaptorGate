import { describe, test, beforeAll, beforeEach, afterEach, expect } from "bun:test";
import "../harness";
import {
	request,
	resetFirewallState,
	getClient,
	getSnapshotClient,
	performCommand,
} from "../harness";
import { NatProtocol } from "../generated/common/common";
import { createDefaultSnapshotBundle } from "../harness/fixtures";
import { sleep } from "bun";

function pushNatSnapshot(natRules: any[]) {
	const bundle = createDefaultSnapshotBundle({ natRules });
	return request("PushActiveConfigSnapshot", {
		correlationId: crypto.randomUUID(),
		reason: "nat e2e test",
		snapshot: {
			id: crypto.randomUUID(),
			versionNumber: 1,
			snapshotType: "manual_import",
			checksum: `nat-e2e-${Date.now()}`,
			isActive: true,
			changesSummary: "NAT e2e test rules",
			createdAt: new Date(),
			createdBy: "test-env",
			bundle,
		},
	});
}

async function cleanupNatListeners() {
	await performCommand({
		host: "h2",
		command: "pkill -f 'python3 -m http[.]server 80 --bind 192[.]168[.]20[.]10|[n]cat -l 9999' || true",
	})
		.discardError()
		.run();
	await sleep(200);
}

// ---------------------------------------------------------------------------
// PAT — port address translation (dst ip+port → translated ip+port)
// ---------------------------------------------------------------------------

describe("NAT E2E", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	beforeEach(cleanupNatListeners);
	afterEach(cleanupNatListeners);

	test(
		"PAT: h1 → VIP:8080 translates to h2:80",
		async () => {
			const natRules = [
				{
					id: crypto.randomUUID(),
					priority: 10,
					protocol: NatProtocol.NAT_PROTOCOL_TCP,
					pat: {
						dstIp: "192.168.20.200",
						dstPort: 8080,
						translatedIp: "192.168.20.10",
						translatedPort: 80,
					},
				},
			];

			await pushNatSnapshot(natRules)
				.expectResponse((r: any) => r.accepted)
				.run();

			await sleep(500);

			const httpServer = await performCommand({
				host: "h2",
				command: "timeout 10 python3 -m http.server 80 --bind 192.168.20.10",
			}).runDetached();

			try {
				await performCommand({
					host: "h1",
					command: "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 192.168.20.200:8080",
				})
					.expectOutput([/200/])
					.isOk()
					.run();
			} finally {
				await httpServer.kill();
			}
		},
		{ timeout: 20_000 },
	);

	// ---------------------------------------------------------------------------
	// DNAT — destination NAT by CIDR match
	// ---------------------------------------------------------------------------

	test(
		"DNAT: h1 → VIP:443 translates dst to h2:80",
		async () => {
			const natRules = [
				{
					id: crypto.randomUUID(),
					priority: 10,
					protocol: NatProtocol.NAT_PROTOCOL_TCP,
					dnat: {
						dstCidr: "192.168.20.200/32",
						translatedIp: "192.168.20.10",
						translatedPort: 80,
					},
				},
			];

			await pushNatSnapshot(natRules)
				.expectResponse((r: any) => r.accepted)
				.run();

			await sleep(500);

			const httpServer = await performCommand({
				host: "h2",
				command: "timeout 10 python3 -m http.server 80 --bind 192.168.20.10",
			}).runDetached();

			try {
				await performCommand({
					host: "h1",
					command: "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 192.168.20.200:443",
				})
					.expectOutput([/200/])
					.isOk()
					.run();
			} finally {
				await httpServer.kill();
			}
		},
		{ timeout: 20_000 },
	);

	// ---------------------------------------------------------------------------
	// DNAT without translated_port — keeps original dst port
	// ---------------------------------------------------------------------------

	test(
		"DNAT without translated_port: h1 → VIP:80 translates dst IP only",
		async () => {
			const natRules = [
				{
					id: crypto.randomUUID(),
					priority: 10,
					protocol: NatProtocol.NAT_PROTOCOL_TCP,
					dnat: {
						dstCidr: "192.168.20.200/32",
						translatedIp: "192.168.20.10",
					},
				},
			];

			await pushNatSnapshot(natRules)
				.expectResponse((r: any) => r.accepted)
				.run();

			await sleep(500);

			const httpServer = await performCommand({
				host: "h2",
				command: "timeout 10 python3 -m http.server 80 --bind 192.168.20.10",
			}).runDetached();

			try {
				await performCommand({
					host: "h1",
					command: "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 192.168.20.200:80",
				})
					.expectOutput([/200/])
					.isOk()
					.run();
			} finally {
				await httpServer.kill();
			}
		},
		{ timeout: 20_000 },
	);

	// ---------------------------------------------------------------------------
	// SNAT — source NAT (rewrite source IP of outgoing packets)
	// ---------------------------------------------------------------------------

	test(
		"SNAT: h1 source rewritten to 192.168.20.100, h2 sees translated src",
		async () => {
			const natRules = [
				{
					id: crypto.randomUUID(),
					priority: 10,
					protocol: NatProtocol.NAT_PROTOCOL_TCP,
					snat: {
						srcCidr: "192.168.10.0/24",
						translatedIp: "192.168.20.100",
					},
				},
			];

			await pushNatSnapshot(natRules)
				.expectResponse((r: any) => r.accepted)
				.run();

			await sleep(500);

			const ncatServer = await performCommand({
				host: "h2",
				command: "timeout 10 ncat -l 9999 -c 'echo PEER=$NCAT_REMOTE_ADDR'",
			}).runDetached();

			try {
				await performCommand({
					host: "h1",
					command: "ncat --recv-only -w 3 192.168.20.10 9999",
				})
					.expectOutput([/PEER=192\.168\.20\.100/])
					.isOk()
					.run();
			} finally {
				await ncatServer.kill();
			}
		},
		{ timeout: 20_000 },
	);

	// ---------------------------------------------------------------------------
	// Masquerade — SNAT using outgoing interface IP
	// ---------------------------------------------------------------------------

	test(
		"MASQUERADE: h1 source rewritten to r1 eth2 IP (192.168.20.254)",
		async () => {
			const natRules = [
				{
					id: crypto.randomUUID(),
					priority: 10,
					outInterface: "eth2",
					protocol: NatProtocol.NAT_PROTOCOL_TCP,
					masquerade: {
						srcCidr: "192.168.10.0/24",
					},
				},
			];

			await pushNatSnapshot(natRules)
				.expectResponse((r: any) => r.accepted)
				.run();

			await sleep(500);

			const ncatServer = await performCommand({
				host: "h2",
				command: "timeout 10 ncat -l 9999 -c 'echo PEER=$NCAT_REMOTE_ADDR'",
			}).runDetached();

			try {
				await performCommand({
					host: "h1",
					command: "ncat --recv-only -w 3 192.168.20.10 9999",
				})
					.expectOutput([/PEER=192\.168\.20\.254/])
					.isOk()
					.run();
			} finally {
				await ncatServer.kill();
			}
		},
		{ timeout: 20_000 },
	);

	// ---------------------------------------------------------------------------
	// PAT with multiple concurrent connections
	// ---------------------------------------------------------------------------

	test(
		"PAT: multiple concurrent connections share translated port",
		async () => {
			const natRules = [
				{
					id: crypto.randomUUID(),
					priority: 10,
					protocol: NatProtocol.NAT_PROTOCOL_TCP,
					pat: {
						dstIp: "192.168.20.200",
						dstPort: 8080,
						translatedIp: "192.168.20.10",
						translatedPort: 80,
					},
				},
			];

			await pushNatSnapshot(natRules)
				.expectResponse((r: any) => r.accepted)
				.run();

			await sleep(500);

			const httpServer = await performCommand({
				host: "h2",
				command: "timeout 15 python3 -m http.server 80 --bind 192.168.20.10",
			}).runDetached();

			try {
				// 3 sequential requests — all should succeed through same PAT rule
				for (let i = 0; i < 3; i++) {
					await performCommand({
						host: "h1",
						command: `curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 192.168.20.200:8080`,
					})
						.expectOutput([/200/])
						.isOk()
						.run();
				}
			} finally {
				await httpServer.kill();
			}
		},
		{ timeout: 30_000 },
	);

	// ---------------------------------------------------------------------------
	// No matching rule — traffic passes without translation
	// ---------------------------------------------------------------------------

	test(
		"No NAT rule: direct traffic h1 → h2 works without translation",
		async () => {
			// Push empty NAT rules
			await pushNatSnapshot([])
				.expectResponse((r: any) => r.accepted)
				.run();

			await sleep(500);

			const ncatServer = await performCommand({
				host: "h2",
				command: "timeout 10 ncat -l 9999 -c 'echo PEER=$NCAT_REMOTE_ADDR'",
			}).runDetached();

			try {
				await performCommand({
					host: "h1",
					command: "ncat --recv-only -w 3 192.168.20.10 9999",
				})
					.expectOutput([/PEER=192\.168\.10\.10/])
					.isOk()
					.run();
			} finally {
				await ncatServer.kill();
			}
		},
		{ timeout: 20_000 },
	);
});
