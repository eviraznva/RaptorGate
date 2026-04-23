import type { Rule, Zone, ZonePair, ZoneInterface, AppConfig } from '../generated/config/config_models';
import { DefaultPolicy } from '../generated/common/common';
import type {
  FirewallConfigSnapshotServiceClient,
  FirewallQueryServiceClient,
} from './grpc-client';
import type { ConfigBundle } from '../generated/services/config_snapshot_service';

export const DEFAULT_APP_CONFIG: AppConfig = {
  captureInterfaces: ['eth1', 'eth2'],
  pcapTimeoutMs: 3000,
  tunDeviceName: 'tun0',
  tunAddress: '10.254.254.1',
  tunNetmask: '255.255.255.0',
  dataDir: '/resources/ngfw/.data',
  eventSocketPath: './sockets/event.sock',
  querySocketPath: '/resources/ngfw/sockets/query.sock',
  pkiDir: '/resources/ngfw/pki',
};

const OUTSIDE_ZONE_ID = crypto.randomUUID();
const INSIDE_ZONE_ID = crypto.randomUUID();

export const DEFAULT_ZONE_INTERFACES: ZoneInterface[] = [
  {
    id: crypto.randomUUID(),
    zoneId: OUTSIDE_ZONE_ID,
    interfaceName: 'eth1',
    status: 0,
    addresses: [],
  },
  {
    id: crypto.randomUUID(),
    zoneId: INSIDE_ZONE_ID,
    interfaceName: 'eth2',
    status: 0,
    addresses: [],
  },
];

export const DEFAULT_ZONES: Zone[] = [
  {
    id: OUTSIDE_ZONE_ID,
    name: 'outside',
    interfaceIds: [DEFAULT_ZONE_INTERFACES[0]!.id],
  },
  {
    id: INSIDE_ZONE_ID,
    name: 'inside',
    interfaceIds: [DEFAULT_ZONE_INTERFACES[1]!.id],
  },
];

export const DEFAULT_ZONE_PAIRS: ZonePair[] = [
  {
    id: crypto.randomUUID(),
    srcZoneId: DEFAULT_ZONES[0]!.id,
    dstZoneId: DEFAULT_ZONES[1]!.id,
    defaultPolicy: DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED,
  },
];

export const DEFAULT_POLICIES: Rule[] = [{
  id: crypto.randomUUID(),
  name: "default_e2e_testing",
  zonePairId: DEFAULT_ZONE_PAIRS[0]!.id,
  priority: 0,
  content: `
		match ip_ver {
			=v4: match protocol {
				|(=icmp =tcp =udp): verdict allow
			}
			= v6: verdict drop
		}
	`
}];

export function createDefaultSnapshotBundle(overrides?: Partial<ConfigBundle>): ConfigBundle {
  const zones = overrides?.zones ?? DEFAULT_ZONES.map((zone) => ({ ...zone }));
  const zonePairs = overrides?.zonePairs ?? DEFAULT_ZONE_PAIRS.map((zonePair) => ({ ...zonePair }));
  
  let rules = overrides?.rules;
  if (!rules) {
    const defaultRule = {
      ...DEFAULT_POLICIES[0]!,
      id: crypto.randomUUID(),
      zonePairId: zonePairs[0]!.id,
    };
    rules = [defaultRule];
  }

  return {
    rules,
    zones,
    zonePairs,
    zoneInterfaces: overrides?.zoneInterfaces ?? DEFAULT_ZONE_INTERFACES.map((zi) => ({ ...zi })),
    natRules: overrides?.natRules ?? [],
    dnsBlacklist: overrides?.dnsBlacklist ?? [],
    sslBypassList: overrides?.sslBypassList ?? [],
    ipsSignatures: overrides?.ipsSignatures ?? [],
    firewallCertificates: overrides?.firewallCertificates ?? [],
    ...(overrides?.mlModel ? { mlModel: overrides.mlModel } : {}),
    ...(overrides?.identity ? { identity: overrides.identity } : {}),
  };
}

export async function resetFirewallState(
  client: FirewallQueryServiceClient,
  snapshotClient: FirewallConfigSnapshotServiceClient,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    client.swapConfig({ config: DEFAULT_APP_CONFIG }, (err: Error | null) => {
      if (err) reject(err);
      else resolve();
    });
  });

  await new Promise<void>((resolve, reject) => {
    snapshotClient.pushActiveConfigSnapshot(
      {
        correlationId: crypto.randomUUID(),
        reason: 'apply',
        snapshot: {
          id: crypto.randomUUID(),
          versionNumber: 1,
          snapshotType: 'manual_import',
          checksum: 'test-env-default-checksum',
          isActive: true,
          changesSummary: 'reset firewall state for test-env',
          createdAt: new Date(),
          createdBy: 'test-env-reset',
          bundle: createDefaultSnapshotBundle(),
        },
      },
      (err: Error | null, resp: any) => {
        if (err) {
          reject(err);
          return;
        }
        if (!resp?.accepted) {
          reject(new Error(resp?.message || 'snapshot reset rejected'));
          return;
        }
        resolve();
      },
    );
  });
}
