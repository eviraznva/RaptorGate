import type { FirewallQueryServiceClient } from './grpc-client';

export const DEFAULT_APP_CONFIG = {
  capture_interfaces: ['eth1', 'eth2'],
  pcap_timeout_ms: 3000,
  tun_device_name: 'tun0',
  tun_address: '10.254.254.1',
  tun_netmask: '255.255.255.0',
  data_dir: '/resources/ngfw/.data',
  event_socket_path: './sockets/firewall.sock',
  query_socket_path: '/resources/ngfw/sockets/query.sock',
  pki_dir: '/resources/ngfw/pki',
};

export const DEFAULT_ZONES = [
  {
    id: crypto.randomUUID(),
    name: 'outside',
    interface_ids: ['eth1'],
  },
  {
    id: crypto.randomUUID(),
    name: 'inside',
    interface_ids: ['eth2'],
  },
];

export const DEFAULT_ZONE_PAIRS = [
  {
    id: crypto.randomUUID(),
    src_zone_id: DEFAULT_ZONES[0]!.id,
    dst_zone_id: DEFAULT_ZONES[1]!.id,
    default_policy: 0,
  },
];

export const DEFAULT_POLICIES: any[] = [];

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
