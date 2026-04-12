import type { Rule, Zone, ZonePair, AppConfig } from '../generated/config/config_models';
import { DefaultPolicy } from '../generated/common/common';
import type { FirewallQueryServiceClient } from './grpc-client';

export const DEFAULT_APP_CONFIG: AppConfig = {
  captureInterfaces: ['eth1', 'eth2'],
  pcapTimeoutMs: 3000,
  tunDeviceName: 'tun0',
  tunAddress: '10.254.254.1',
  tunNetmask: '255.255.255.0',
  dataDir: '/resources/ngfw/.data',
  eventSocketPath: './sockets/firewall.sock',
  querySocketPath: '/resources/ngfw/sockets/query.sock',
  pkiDir: '/resources/ngfw/pki',
};

export const DEFAULT_ZONES: Zone[] = [
  {
    id: crypto.randomUUID(),
    name: 'outside',
    interfaceIds: ['eth1'],
  },
  {
    id: crypto.randomUUID(),
    name: 'inside',
    interfaceIds: ['eth2'],
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

export async function resetFirewallState(client: FirewallQueryServiceClient): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    client.swapConfig({ config: DEFAULT_APP_CONFIG }, (err: Error | null) => {
      if (err) reject(err);
      else resolve();
    });
  });

  await new Promise<void>((resolve, reject) => {
    client.swapZones({ zones: DEFAULT_ZONES }, (err: Error | null) => {
      if (err) reject(err);
      else resolve();
    });
  });

  await new Promise<void>((resolve, reject) => {
    client.swapZonePairs({ zone_pairs: DEFAULT_ZONE_PAIRS }, (err: Error | null) => {
      if (err) reject(err);
      else resolve();
    });
  });

  await new Promise<void>((resolve, reject) => {
    client.swapPolicies({ rules: DEFAULT_POLICIES }, (err: Error | null) => {
      if (err) reject(err);
      else resolve();
    });
  });
}
