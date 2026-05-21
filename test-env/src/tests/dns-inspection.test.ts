import { describe, test, beforeAll, afterAll } from "bun:test";
import "../harness";
import {
	request,
	performCommand,
	resetFirewallState,
	getClient,
	getSnapshotClient,
	DetachedCommand,
} from "../harness";
import {
	createDefaultSnapshotBundle,
	DEFAULT_POLICIES,
} from "../harness/fixtures";
import type {
	DnsInspectionConfig,
	DnsInspectionGeneralConfig,
	DnsInspectionBlocklistConfig,
	DnsInspectionDnsTunnelingConfig,
	DnsInspectionDnssecConfig,
	DnsInspectionEchMitigationConfig,
} from "../generated/config/config_models";
import {
	DnsInspectionDnssecFailureAction,
	DnsInspectionDnssecTransport,
} from "../generated/config/config_models";
import type { ConfigBundle } from "../generated/services/config_snapshot_service";

const DNS_TARGET = "192.168.20.10";
const DNS_PORT = 53535;

const DNS_QUERY_SCRIPT = `import sys
from scapy.all import DNS, DNSQR, IP, UDP, sr1
ans = sr1(IP(dst="${DNS_TARGET}")/UDP(dport=${DNS_PORT})/DNS(rd=1, qd=DNSQR(qname=sys.argv[1])), timeout=3, verbose=0)
print("RESULT=REPLY" if ans else "RESULT=NO_REPLY")
`;

const SCRIPT_B64 = Buffer.from(DNS_QUERY_SCRIPT).toString("base64");
const SCRIPT_PATH = "/tmp/dns_query.py";
const FLOOD_SCRIPT_PATH = "/tmp/dns_flood.py";
const SERVER_SCRIPT_PATH = "/tmp/dns_responder.py";

const DNS_FLOOD_SCRIPT = `import sys, secrets
from scapy.all import DNS, DNSQR, IP, UDP, sr1
suffix = sys.argv[1]
count = int(sys.argv[2])
replies = 0
no_replies = 0
sr1(IP(dst="${DNS_TARGET}")/UDP(dport=${DNS_PORT})/DNS(rd=1, qd=DNSQR(qname="warmup." + suffix)), timeout=2, verbose=0)
for i in range(count):
    label = secrets.token_hex(16)
    ans = sr1(IP(dst="${DNS_TARGET}")/UDP(dport=${DNS_PORT})/DNS(rd=1, qd=DNSQR(qname=label + "." + suffix)), timeout=2, verbose=0)
    if ans:
        replies += 1
    else:
        no_replies += 1
print("REPLIES=" + str(replies))
print("NO_REPLIES=" + str(no_replies))
`;

const FLOOD_B64 = Buffer.from(DNS_FLOOD_SCRIPT).toString("base64");

const DNS_SERVER_SCRIPT = `import socket, struct, sys
port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", port))
while True:
    data, addr = sock.recvfrom(512)
    if len(data) < 12:
        continue
    off = 12
    while off < len(data) and data[off] != 0:
        off += data[off] + 1
    if off + 5 > len(data):
        continue
    question = data[12:off + 5]
    qtype = data[off + 1:off + 3]
    qclass = data[off + 3:off + 5]
    answer = b"\\xc0\\x0c" + qtype + qclass + struct.pack("!I", 60) + struct.pack("!H", 4) + bytes([203, 0, 113, 10])
    response = data[:2] + b"\\x81\\x80" + data[4:6] + b"\\x00\\x01\\x00\\x00\\x00\\x00" + question + answer
    sock.sendto(response, addr)
`;

const SERVER_B64 = Buffer.from(DNS_SERVER_SCRIPT).toString("base64");

let dnsServer: DetachedCommand | undefined;

function defaultGeneral(
	overrides: Partial<DnsInspectionGeneralConfig> = {},
): DnsInspectionGeneralConfig {
	return { enabled: false, ...overrides };
}

function defaultBlocklist(
	overrides: Partial<DnsInspectionBlocklistConfig> = {},
): DnsInspectionBlocklistConfig {
	return { enabled: false, domains: [], ...overrides };
}

function defaultTunneling(
	overrides: Partial<DnsInspectionDnsTunnelingConfig> = {},
): DnsInspectionDnsTunnelingConfig {
	return {
		enabled: false,
		maxLabelLength: 40,
		entropyThreshold: 3.5,
		windowSeconds: 60,
		maxQueriesPerDomain: 100,
		maxUniqueSubdomains: 20,
		ignoreDomains: [],
		alertThreshold: 0.6,
		blockThreshold: 0.85,
		...overrides,
	};
}

function defaultDnssec(
	overrides: Partial<DnsInspectionDnssecConfig> = {},
): DnsInspectionDnssecConfig {
	return {
		enabled: false,
		maxLookupsPerPacket: 1,
		defaultOnResolverFailure:
			DnsInspectionDnssecFailureAction.DNS_INSPECTION_DNSSEC_FAILURE_ACTION_ALLOW,
		resolver: {
			primary: { address: "127.0.0.1", port: 53 },
			transport:
				DnsInspectionDnssecTransport.DNS_INSPECTION_DNSSEC_TRANSPORT_UDP_WITH_TCP_FALLBACK,
			timeoutMs: 2000,
			retries: 1,
		},
		cache: {
			enabled: true,
			maxEntries: 4096,
			ttlSeconds: { secure: 300, insecure: 300, bogus: 60, failure: 15 },
		},
		...overrides,
	};
}

function defaultEch(
	overrides: Partial<DnsInspectionEchMitigationConfig> = {},
): DnsInspectionEchMitigationConfig {
	return { stripEchDns: true, logEchAttempts: true, ...overrides };
}

function makeDnsConfig(opts: {
	general?: Partial<DnsInspectionGeneralConfig>;
	blocklist?: Partial<DnsInspectionBlocklistConfig>;
	dnsTunneling?: Partial<DnsInspectionDnsTunnelingConfig>;
	dnssec?: Partial<DnsInspectionDnssecConfig>;
	echMitigation?: Partial<DnsInspectionEchMitigationConfig>;
}): DnsInspectionConfig {
	return {
		general: defaultGeneral(opts.general),
		blocklist: defaultBlocklist(opts.blocklist),
		dnsTunneling: defaultTunneling(opts.dnsTunneling),
		dnssec: defaultDnssec(opts.dnssec),
		echMitigation: defaultEch(opts.echMitigation),
	};
}

function buildPermissiveBundle(dns: DnsInspectionConfig): ConfigBundle {
	const defaultRule = DEFAULT_POLICIES[0]!;
	return createDefaultSnapshotBundle({
		rules: [
			{
				...defaultRule,
				id: crypto.randomUUID(),
				name: "dns-inspection-test",
				content: "match ip_ver { =v4: verdict allow }",
				zonePairId: defaultRule.zonePairId,
			},
		],
		dnsInspectionConfig: dns,
	});
}

async function pushDnsSnapshot(dns: DnsInspectionConfig): Promise<void> {
	await request("PushActiveConfigSnapshot", {
		correlationId: crypto.randomUUID(),
		reason: "apply",
		snapshot: {
			id: crypto.randomUUID(),
			versionNumber: 1,
			snapshotType: "manual_import",
			checksum: `dns-inspection-${crypto.randomUUID()}`,
			isActive: true,
			changesSummary: "dns-inspection test snapshot",
			createdAt: new Date(),
			createdBy: "dns-inspection-test",
			bundle: buildPermissiveBundle(dns),
		},
	}).run();
}

async function dnsQuery(domain: string, expectReply: boolean): Promise<void> {
	const regex = expectReply ? /^RESULT=REPLY$/ : /^RESULT=NO_REPLY$/;
	await performCommand({
		host: "h1",
		command: `sudo python3 ${SCRIPT_PATH} ${domain}`,
	})
		.expectOutput([regex])
		.run();
}

describe("DNS Inspection", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
		await performCommand({
			host: "h2",
			command: `sudo fuser -k ${DNS_PORT}/udp || true`,
		}).run();
		await performCommand({
			host: "h1",
			command: `echo ${SCRIPT_B64} | base64 -d | sudo tee ${SCRIPT_PATH} > /dev/null`,
		}).run();
		await performCommand({
			host: "h1",
			command: `echo ${FLOOD_B64} | base64 -d | sudo tee ${FLOOD_SCRIPT_PATH} > /dev/null`,
		}).run();
		await performCommand({
			host: "h2",
			command: `echo ${SERVER_B64} | base64 -d | tee ${SERVER_SCRIPT_PATH} > /dev/null`,
		}).run();
		dnsServer = await performCommand({
			host: "h2",
			command: `python3 -u ${SERVER_SCRIPT_PATH} ${DNS_PORT} 2>&1`,
		}).runDetached();
	});

	afterAll(async () => {
		await dnsServer?.kill();
	});

	test(
		"master disabled bypasses blocklist",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: false },
					blocklist: { enabled: true, domains: ["example.com"] },
				}),
			);
			await dnsQuery("example.com", true);
		},
		{ timeout: 30000 },
	);

	test(
		"blocklist exact match drops query",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					blocklist: { enabled: true, domains: ["example.com"] },
				}),
			);
			await dnsQuery("example.com", false);
		},
		{ timeout: 30000 },
	);

	test(
		"blocklist allows non-listed domain",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					blocklist: { enabled: true, domains: ["example.com"] },
				}),
			);
			await dnsQuery("cloudflare.com", true);
		},
		{ timeout: 30000 },
	);

	test(
		"blocklist disabled lets listed domain through",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					blocklist: { enabled: false, domains: ["example.com"] },
				}),
			);
			await dnsQuery("example.com", true);
		},
		{ timeout: 30000 },
	);

	test(
		"blocklist wildcard blocks subdomain",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					blocklist: { enabled: true, domains: ["*.example.com"] },
				}),
			);
			await dnsQuery("www.example.com", false);
		},
		{ timeout: 30000 },
	);

	test(
		"blocklist wildcard does not match apex",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					blocklist: { enabled: true, domains: ["*.example.com"] },
				}),
			);
			await dnsQuery("example.com", true);
		},
		{ timeout: 30000 },
	);

	test(
		"tunneling detector blocks high-entropy flood",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					dnsTunneling: {
						enabled: true,
						maxUniqueSubdomains: 5,
						maxQueriesPerDomain: 5,
						entropyThreshold: 2.5,
						alertThreshold: 0.4,
						blockThreshold: 0.5,
						windowSeconds: 60,
					},
				}),
			);
		await performCommand({
			host: "h1",
			command: `sudo python3 ${FLOOD_SCRIPT_PATH} tunnel-test.com 12`,
		})
				.expectOutput([/^NO_REPLIES=([1-9]\d*)$/])
				.run();
		},
		{ timeout: 120000 },
	);

	test(
		"tunneling ignoreDomains lets flood through",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					dnsTunneling: {
						enabled: true,
						maxUniqueSubdomains: 5,
						maxQueriesPerDomain: 5,
						entropyThreshold: 2.5,
						alertThreshold: 0.4,
						blockThreshold: 0.5,
						windowSeconds: 60,
						ignoreDomains: ["*.example.com"],
					},
				}),
			);
			await performCommand({
				host: "h1",
				command: `sudo python3 ${FLOOD_SCRIPT_PATH} example.com 15`,
			})
				.expectOutput([/^NO_REPLIES=0$/])
				.run();
		},
		{ timeout: 120000 },
	);

	test(
		"dnssec config is accepted with udp_with_tcp_fallback transport",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					dnssec: {
						enabled: true,
						maxLookupsPerPacket: 2,
						defaultOnResolverFailure:
							DnsInspectionDnssecFailureAction.DNS_INSPECTION_DNSSEC_FAILURE_ACTION_ALERT,
						resolver: {
							primary: { address: "8.8.8.8", port: 53 },
							secondary: { address: "1.1.1.1", port: 53 },
							transport:
								DnsInspectionDnssecTransport.DNS_INSPECTION_DNSSEC_TRANSPORT_UDP_WITH_TCP_FALLBACK,
							timeoutMs: 2500,
							retries: 2,
						},
						cache: {
							enabled: true,
							maxEntries: 1024,
							ttlSeconds: {
								secure: 600,
								insecure: 300,
								bogus: 30,
								failure: 10,
							},
						},
					},
				}),
			);
		},
		{ timeout: 30000 },
	);

	test(
		"ech mitigation config is accepted",
		async () => {
			await pushDnsSnapshot(
				makeDnsConfig({
					general: { enabled: true },
					echMitigation: { stripEchDns: true, logEchAttempts: true },
				}),
			);
			await dnsQuery("example.com", true);
		},
		{ timeout: 30000 },
	);
});
