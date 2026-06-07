import { describe, test, beforeAll, afterAll } from "bun:test";
import "../harness";
import {
	request,
	performCommand,
	DetachedCommand,
	resetFirewallState,
	getClient,
	getSnapshotClient,
} from "../harness";
import {
	createDefaultSnapshotBundle,
	DEFAULT_POLICIES,
} from "../harness/fixtures";
import {
	IpsAction,
	IpsAppProtocol,
	IpsMatchType,
	IpsPatternEncoding,
} from "../generated/config/config_models";
import { Severity } from "../generated/common/common";
import type {
	IpsConfig,
	IpsGeneralConfig,
	IpsDetectionConfig,
	IpsSignatureConfig,
} from "../generated/config/config_models";
import type { ConfigBundle } from "../generated/services/config_snapshot_service";

const HTTP_SERVER_PORT = 18080;
const HTTP_SERVER_HOST = "192.168.20.10";

function defaultGeneral(
	overrides: Partial<IpsGeneralConfig> = {},
): IpsGeneralConfig {
	return { enabled: true, ...overrides };
}

function defaultDetection(
	overrides: Partial<IpsDetectionConfig> = {},
): IpsDetectionConfig {
	return {
		enabled: true,
		maxPayloadBytes: 4096,
		maxMatchesPerPacket: 8,
		...overrides,
	};
}

function makeSignature(
	overrides: Partial<IpsSignatureConfig> & Pick<IpsSignatureConfig, "id" | "name" | "pattern">,
): IpsSignatureConfig {
	return {
		enabled: true,
		category: "other",
		matchType: IpsMatchType.IPS_MATCH_TYPE_REGEX,
		patternEncoding: IpsPatternEncoding.IPS_PATTERN_ENCODING_TEXT,
		caseInsensitive: false,
		severity: Severity.SEVERITY_HIGH,
		action: IpsAction.IPS_ACTION_BLOCK,
		appProtocols: [],
		srcPorts: [],
		dstPorts: [],
		...overrides,
	};
}

function makeIpsConfig(opts: {
	general?: Partial<IpsGeneralConfig>;
	detection?: Partial<IpsDetectionConfig>;
	signatures?: IpsSignatureConfig[];
}): IpsConfig {
	return {
		general: defaultGeneral(opts.general),
		detection: defaultDetection(opts.detection),
		signatures: opts.signatures ?? [],
	};
}

function buildBundle(ips: IpsConfig): ConfigBundle {
	const defaultRule = DEFAULT_POLICIES[0]!;
	return createDefaultSnapshotBundle({
		rules: [
			{
				...defaultRule,
				id: crypto.randomUUID(),
				name: "ips-test",
				content: "match ip_ver { =v4: verdict allow }",
				zonePairId: defaultRule.zonePairId,
			},
		],
		ipsConfig: ips,
	});
}

async function pushIpsSnapshot(ips: IpsConfig): Promise<void> {
	await request("PushActiveConfigSnapshot", {
		correlationId: crypto.randomUUID(),
		reason: "apply",
		snapshot: {
			id: crypto.randomUUID(),
			versionNumber: 1,
			snapshotType: "manual_import",
			checksum: `ips-${crypto.randomUUID()}`,
			isActive: true,
			changesSummary: "ips test snapshot",
			createdAt: new Date(),
			createdBy: "ips-test",
			bundle: buildBundle(ips),
		},
	}).run();
}

let httpServer: DetachedCommand | null = null;

async function startHttpServer(): Promise<void> {
	await performCommand({
		host: "h2",
		command: `sudo pkill -9 -f 'http.server ${HTTP_SERVER_PORT}|[n]cat -lk 0[.]0[.]0[.]0 ${HTTP_SERVER_PORT}'; sleep 1; true`,
	})
		.discardError()
		.run();

	httpServer = await performCommand({
		host: "h2",
		command: `timeout 120 ncat -lk 0.0.0.0 ${HTTP_SERVER_PORT} -c 'awk '\\''{ if ($0 == "\\r") exit }'\\''; printf "HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok"'`,
	}).runDetached();

	await performCommand({
		host: "h2",
		command: `for i in 1 2 3 4 5 6 7 8 9 10; do curl -fsS --max-time 1 http://127.0.0.1:${HTTP_SERVER_PORT}/ -o /dev/null && exit 0; sleep 0.5; done; exit 1`,
	}).run();
}

async function stopHttpServer(): Promise<void> {
	if (httpServer) {
		await httpServer.kill();
		httpServer = null;
	}
}

async function httpRequest(payload: string, expectReply: boolean): Promise<void> {
	const headerPayload = payload.replaceAll("'", "'\\''");
	const command =
		`curl --silent --show-error --max-time 4 ` +
		`--header 'X-RaptorGate-Test: ${headerPayload}' ` +
		`--write-out 'STATUS=%{http_code}\\n' --output /dev/null ` +
		`'http://${HTTP_SERVER_HOST}:${HTTP_SERVER_PORT}/'; ` +
		`code=$?; echo CURL_EXIT=$code; exit $code`;

	const builder = performCommand({ host: "h1", command });

	if (expectReply) {
		await builder.expectOutput([/^STATUS=200$/]).run();
	} else {
		await builder.discardError().expectOutput([/^CURL_EXIT=([1-9]\d*)$/]).run();
	}
}

const SQLI_PAYLOAD = "UNION SELECT 1";

describe("IPS", () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
		await startHttpServer();
	});

	afterAll(async () => {
		await stopHttpServer();
	});

	test(
		"block regex signature drops sqli request",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					signatures: [
						makeSignature({
							id: "ips-sqli",
							name: "SQLi Union Select",
							category: "sqli",
							pattern: "(?i)union\\s+select",
							action: IpsAction.IPS_ACTION_BLOCK,
						}),
					],
				}),
			);
			await httpRequest(SQLI_PAYLOAD, false);
		},
		{ timeout: 30000 },
	);

	test(
		"alert signature passes traffic and emits event",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					signatures: [
						makeSignature({
							id: "ips-curl-ua",
							name: "Curl UA",
							category: "recon",
							pattern: "(?i)curl/",
							severity: Severity.SEVERITY_LOW,
							action: IpsAction.IPS_ACTION_ALERT,
						}),
					],
				}),
			);

			await performCommand({
				host: "h1",
				command:
					`curl --silent --max-time 4 --write-out 'STATUS=%{http_code}\\n' ` +
					`--output /dev/null http://${HTTP_SERVER_HOST}:${HTTP_SERVER_PORT}/`,
			})
				.expectOutput([/^STATUS=200$/])
				.expectEvents([
					{
						kind: "ipsSignatureMatched",
						match: {
							signatureId: "ips-curl-ua",
							action: "alert",
							severity: "low",
						},
					},
				])
				.run();
		},
		{ timeout: 30000 },
	);

	test(
		"master disabled bypasses detection",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					general: { enabled: false },
					signatures: [
						makeSignature({
							id: "ips-sqli",
							name: "SQLi",
							pattern: "(?i)union\\s+select",
						}),
					],
				}),
			);
			await httpRequest(SQLI_PAYLOAD, true);
		},
		{ timeout: 30000 },
	);

	test(
		"detection disabled bypasses inspection",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					detection: { enabled: false },
					signatures: [
						makeSignature({
							id: "ips-sqli",
							name: "SQLi",
							pattern: "(?i)union\\s+select",
						}),
					],
				}),
			);
			await httpRequest(SQLI_PAYLOAD, true);
		},
		{ timeout: 30000 },
	);

	test(
		"disabled signature is ignored",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					signatures: [
						makeSignature({
							id: "ips-sqli",
							name: "SQLi",
							pattern: "(?i)union\\s+select",
							enabled: false,
						}),
					],
				}),
			);
			await httpRequest(SQLI_PAYLOAD, true);
		},
		{ timeout: 30000 },
	);

	test(
		"literal signature blocks exact match",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					signatures: [
						makeSignature({
							id: "ips-literal",
							name: "Literal Block",
							pattern: "UNION SELECT",
							matchType: IpsMatchType.IPS_MATCH_TYPE_LITERAL,
							caseInsensitive: true,
						}),
					],
				}),
			);
			await httpRequest("union select 1", false);
		},
		{ timeout: 30000 },
	);

	test(
		"dst port filter limits matching scope",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					signatures: [
						makeSignature({
							id: "ips-sqli-port80",
							name: "SQLi on 80",
							pattern: "(?i)union\\s+select",
							dstPorts: [80],
						}),
					],
				}),
			);
			await httpRequest(SQLI_PAYLOAD, true);
		},
		{ timeout: 30000 },
	);

	test(
		"app protocol filter excludes unmatched proto",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					signatures: [
						makeSignature({
							id: "ips-sqli-dns",
							name: "SQLi DNS only",
							pattern: "(?i)union\\s+select",
							appProtocols: [IpsAppProtocol.IPS_APP_PROTOCOL_DNS],
						}),
					],
				}),
			);
			await httpRequest(SQLI_PAYLOAD, true);
		},
		{ timeout: 30000 },
	);

	test(
		"config hot swap replaces active signatures",
		async () => {
			await pushIpsSnapshot(
				makeIpsConfig({
					signatures: [
						makeSignature({
							id: "ips-sqli",
							name: "SQLi",
							pattern: "(?i)union\\s+select",
						}),
					],
				}),
			);
			await httpRequest(SQLI_PAYLOAD, false);

			await pushIpsSnapshot(
				makeIpsConfig({
					signatures: [
						makeSignature({
							id: "ips-other",
							name: "Different",
							pattern: "(?i)xxe\\s+payload",
						}),
					],
				}),
			);
			await httpRequest(SQLI_PAYLOAD, true);
		},
		{ timeout: 60000 },
	);

	test(
		"invalid regex signature is rejected by snapshot apply",
		async () => {
			await request("PushActiveConfigSnapshot", {
				correlationId: crypto.randomUUID(),
				reason: "apply",
				snapshot: {
					id: crypto.randomUUID(),
					versionNumber: 1,
					snapshotType: "manual_import",
					checksum: `ips-invalid-${crypto.randomUUID()}`,
					isActive: true,
					changesSummary: "ips invalid regex snapshot",
					createdAt: new Date(),
					createdBy: "ips-test",
					bundle: buildBundle(
						makeIpsConfig({
							signatures: [
								makeSignature({
									id: "ips-bad",
									name: "Bad Regex",
									pattern: "(",
								}),
							],
						}),
					),
				},
			})
				.expectResponse({ accepted: false })
				.run();
		},
		{ timeout: 30000 },
	);
});
