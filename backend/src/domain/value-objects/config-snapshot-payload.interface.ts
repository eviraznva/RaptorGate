import { FirewallCertificate } from '../entities/firewall-certificate.entity.js';
import { DnsBlacklistEntry } from '../entities/dns-blacklist-entry.entity.js';
import { IdentityAuthenticationProfile } from '../entities/identity-authentication-profile.entity.js';
import { IdentitySettings } from '../entities/identity-settings.entity.js';
import { LdapServerProfile } from '../entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../entities/radius-server-profile.entity.js';
import { SslBypassEntry } from '../entities/ssl-bypass-entry.entity.js';
import { ZoneInterface } from '../entities/zone-interface.entity.js';
import { FirewallRule } from '../entities/firewall-rule.entity.js';
import { IpsSignature } from '../entities/ips-signature.entity.js';
import { ZonePair } from '../entities/zone-pair.entity.js';
import { MlModel } from '../entities/ml-model.entity.js';
import { NatRule } from '../entities/nat-rule.entity.js';
import { Zone } from '../entities/zone.entity.js';
import { User } from '../entities/user.entity.js';

export interface TlsInspectionPolicyPayload {
  block_ech_no_sni: boolean;
  block_all_ech: boolean;
  strip_ech_dns: boolean;
  log_ech_attempts: boolean;
  known_pinned_domains: string[];
  decryption_mirror: DecryptionMirrorConfigPayload;
}

export interface DecryptionMirrorConfigPayload {
  enabled: boolean;
  target_host: string;
  target_port: number;
  include_client_to_server: boolean;
  include_server_to_client: boolean;
  forwarded_only: boolean;
  max_session_bytes: number;
}

export const DEFAULT_TLS_INSPECTION_POLICY: Readonly<TlsInspectionPolicyPayload> =
  {
    block_ech_no_sni: true,
    block_all_ech: false,
    strip_ech_dns: true,
    log_ech_attempts: true,
    known_pinned_domains: [],
    decryption_mirror: {
      enabled: false,
      target_host: '',
      target_port: 0,
      include_client_to_server: true,
      include_server_to_client: true,
      forwarded_only: true,
      max_session_bytes: 16 * 1024 * 1024,
    },
  };

export function normalizeTlsInspectionPolicy(
  policy?: Partial<TlsInspectionPolicyPayload> | null,
): TlsInspectionPolicyPayload {
  return {
    ...DEFAULT_TLS_INSPECTION_POLICY,
    ...(policy ?? {}),
    known_pinned_domains: [...(policy?.known_pinned_domains ?? [])],
    decryption_mirror: {
      ...DEFAULT_TLS_INSPECTION_POLICY.decryption_mirror,
      ...(policy?.decryption_mirror ?? {}),
    },
  };
}

export interface IdentityConfigBundlePayload {
  radius_server_profiles: { items: RadiusServerProfile[] };
  ldap_server_profiles: { items: LdapServerProfile[] };
  authentication_profiles: { items: IdentityAuthenticationProfile[] };
  settings: IdentitySettings;
}

export function emptyIdentityConfigPayload(): IdentityConfigBundlePayload {
  return {
    radius_server_profiles: { items: [] },
    ldap_server_profiles: { items: [] },
    authentication_profiles: { items: [] },
    settings: IdentitySettings.create(null, null, null, null),
  };
}

export interface ConfigBundlePayload {
  rules: { items: FirewallRule[] };
  zones: { items: Zone[] };
  zone_interfaces: { items: ZoneInterface[] };
  zone_pairs: { items: ZonePair[] };
  nat_rules: { items: NatRule[] };
  dns_blacklist: { items: DnsBlacklistEntry[] };
  ssl_bypass_list: { items: SslBypassEntry[] };
  ips_signatures: { items: IpsSignature[] };
  ml_model: MlModel | null;
  firewall_certificates: { items: FirewallCertificate[] };
  tls_inspection_policy?: TlsInspectionPolicyPayload | null;
  identity_config: IdentityConfigBundlePayload;
  users: { items: User[] };
  // roles: { items: Role[] };
  // permissions: { items: Permission[] };
  // role_permissions: { items: RolePermission[] };
  // user_roles: { items: UserRole[] };
}

// ── Root ──────────────────────────────────────────────────────────────────────
export interface ConfigSnapshotPayload {
  bundle: ConfigBundlePayload;
}
