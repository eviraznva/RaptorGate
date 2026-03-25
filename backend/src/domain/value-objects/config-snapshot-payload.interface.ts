export interface ConfigSectionVersions {
  rules: number;
  zones: number;
  zone_interfaces: number;
  zone_pairs: number;
  nat_rules: number;
  dns_blacklist: number;
  ssl_bypass_list: number;
  ips_signatures: number;
  ml_model: number;
  certificates: number;
  identity: number;
}

// ── Reguły ───────────────────────────────────────────────────────────────────
export interface RulePayload {
  id: string;
  name: string;
  zone_pair_id: string;
  priority: number;
  content: string;
}

export interface RulesBundlePayload {
  checksum: string;
  items: RulePayload[];
}

// ── Strefy ───────────────────────────────────────────────────────────────────
export interface ZonePayload {
  id: string;
  name: string;
}

// ── Interfejsy stref ─────────────────────────────────────────────────────────
export interface ZoneInterfacePayload {
  id: string;
  zone_id: string;
  interface_name: string;
  vlan_id: number | null;
}

// ── Pary stref ───────────────────────────────────────────────────────────────
export type DefaultPolicyPayload = 'ALLOW' | 'DROP';
export interface ZonePairPayload {
  id: string;
  src_zone_id: string;
  dst_zone_id: string;
  default_policy: DefaultPolicyPayload;
}

// ── NAT ──────────────────────────────────────────────────────────────────────
export type NatRuleTypePayload = 'SNAT' | 'DNAT' | 'PAT';
export interface NatRulePayload {
  id: string;
  type: NatRuleTypePayload;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  translated_ip: string;
  translated_port: number | null;
  priority: number;
}

// ── DNS blacklista ────────────────────────────────────────────────────────────
export interface DnsBlacklistPayload {
  id: string;
  domain: string;
}

// ── SSL bypass ────────────────────────────────────────────────────────────────
export interface SslBypassPayload {
  id: string;
  domain: string;
}

// ── Sygnatury IPS ─────────────────────────────────────────────────────────────
export type SeverityPayload = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export interface IpsSignaturePayload {
  id: string;
  name: string;
  category: string;
  pattern: string;
  severity: SeverityPayload;
}

// ── Model ML ─────────────────────────────────────────────────────────────────
export interface MlModelPayload {
  id: string;
  name: string;
  artifact_path: string;
  checksum: string;
}

// ── Certyfikaty ───────────────────────────────────────────────────────────────
export type CertificateTypePayload = 'CA' | 'TLS_SERVER';
export interface FirewallCertificatePayload {
  id: string;
  cert_type: CertificateTypePayload;
  common_name: string;
  fingerprint: string;
  certificate_pem: string;
  private_key_ref: string;
  expires_at: string; // ISO 8601
}

// ── Tożsamość ─────────────────────────────────────────────────────────────────
export type IdentitySourcePayload = 'LOCAL' | 'RADIUS' | 'ACTIVE_DIRECTORY';
export interface UserGroupPayload {
  id: string;
  name: string;
  source: IdentitySourcePayload;
}

export interface IdentityUserPayload {
  id: string;
  username: string;
  display_name: string;
  source: IdentitySourcePayload;
  external_id: string;
}

export interface UserGroupMemberPayload {
  id: string;
  group_id: string;
  identity_user_id: string;
}

export interface UserSessionPayload {
  id: string;
  identity_user_id: string;
  radius_username: string;
  mac_address: string;
  ip_address: string;
  nas_ip: string;
  called_station_id: string;
  authenticated_at: string; // ISO 8601
  expires_at: string; // ISO 8601
}

export interface IdentityPayload {
  user_groups: UserGroupPayload[];
  identity_users: IdentityUserPayload[];
  user_group_members: UserGroupMemberPayload[];
  user_sessions: UserSessionPayload[];
}

// ── Bundle (sekcje konfiguracji) ─────────────────────────────────────────────
export interface ConfigBundlePayload {
  rules: RulesBundlePayload;
  zones: { items: ZonePayload[] };
  zone_interfaces: { items: ZoneInterfacePayload[] };
  zone_pairs: { items: ZonePairPayload[] };
  nat_rules: { items: NatRulePayload[] };
  dns_blacklist: { items: DnsBlacklistPayload[] };
  ssl_bypass_list: { items: SslBypassPayload[] };
  ips_signatures: { items: IpsSignaturePayload[] };
  ml_model: MlModelPayload;
  firewall_certificates: { items: FirewallCertificatePayload[] };
  identity: IdentityPayload;
}

// ── Root ──────────────────────────────────────────────────────────────────────
export interface ConfigSnapshotPayload {
  section_versions: ConfigSectionVersions;
  bundle: ConfigBundlePayload;
}
