import type { ConfigSnapshot } from "./types";

export const CONFIG_CONTROL_SNAPSHOTS: ConfigSnapshot[] = [
  {
    id: "5f4e635f-d6d5-4ce4-a8ff-bf8d7184db11",
    versionNumber: 27,
    snapshotType: "manual_import",
    checksum:
      "0374c1e803e24d736cf3794e75a78aa994c10e269f54b07e405f4d52600f12fc",
    isActive: true,
    payloadJson: {
      bundle: {
        rules: { items: [{ id: "rule-1" }, { id: "rule-2" }] },
        zones: { items: [{ id: "zone-wan" }, { id: "zone-lan" }] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [{ id: "pair-wan-lan" }] },
        nat_rules: { items: [{ id: "nat-1" }] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [{ id: "ssl-1" }] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [{ id: "cert-1" }] },
        tls_inspection_policy: {
          block_ech_no_sni: true,
          block_all_ech: false,
          strip_ech_dns: true,
          log_ech_attempts: true,
          known_pinned_domains: [],
        },
        users: { items: [{ id: "user-1" }, { id: "user-2" }] },
      },
    },
    changeSummary: "Imported baseline config from staging",
    createdAt: "2026-04-23T12:03:40Z",
    createdBy: "bf80373d-7e8a-4648-b02f-2fcc7d7d7674",
  },
  {
    id: "2ad0f406-cd66-4f94-9e3f-bcbc9af2f62f",
    versionNumber: 26,
    snapshotType: "rollback_point",
    checksum:
      "e5309542d4a8bbbf0fb98d89b8a3c791e8ee2ca41357f91650a73f6df90b0ece",
    isActive: false,
    payloadJson: {
      bundle: {
        rules: { items: [{ id: "rule-1" }] },
        zones: { items: [{ id: "zone-wan" }, { id: "zone-lan" }] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [{ id: "pair-wan-lan" }] },
        nat_rules: { items: [{ id: "nat-legacy" }] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [{ id: "cert-1" }] },
        tls_inspection_policy: {
          block_ech_no_sni: true,
          block_all_ech: false,
          strip_ech_dns: false,
          log_ech_attempts: true,
          known_pinned_domains: ["bank.example"],
        },
        users: { items: [{ id: "user-1" }] },
      },
    },
    changeSummary: "Rollback point before policy engine update",
    createdAt: "2026-04-22T22:15:12Z",
    createdBy: "25dc46e4-c0c8-4306-86c6-f7a9c7f54857",
  },
  {
    id: "87498e5b-e6ad-4ef7-b1d9-f6439ff6ec96",
    versionNumber: 25,
    snapshotType: "auto_save",
    checksum:
      "704f7598ca45f8f6099fcf57fd7ef0e4f13c4a1648f44f0ee6bf7106fd7bc4ff",
    isActive: false,
    payloadJson: {
      bundle: {
        rules: { items: [{ id: "rule-1" }] },
        zones: { items: [{ id: "zone-wan" }] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [] },
        nat_rules: { items: [] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [] },
        tls_inspection_policy: {
          block_ech_no_sni: true,
          block_all_ech: false,
          strip_ech_dns: true,
          log_ech_attempts: true,
          known_pinned_domains: [],
        },
        users: { items: [{ id: "user-1" }] },
      },
    },
    changeSummary: "Auto save from nightly maintenance",
    createdAt: "2026-04-22T02:10:01Z",
    createdBy: "8a644f16-0b5f-4ec8-9f79-30a1d0e0f942",
  },
];

export function formatSnapshotDate(value: string): string {
  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString("pl-PL", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

export function shortenChecksum(checksum: string): string {
  return `${checksum.slice(0, 12)}...${checksum.slice(-8)}`;
}

export function shortenId(value: string): string {
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}
