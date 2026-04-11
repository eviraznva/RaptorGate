import { FirewallCertificate } from '../entities/firewall-certificate.entity.js';
import { DnsBlacklistEntry } from '../entities/dns-blacklist-entry.entity.js';
import { SslBypassEntry } from '../entities/ssl-bypass-entry.entity.js';
import { ZoneInterface } from '../entities/zone-interface.entity.js';
import { FirewallRule } from '../entities/firewall-rule.entity.js';
import { IpsSignature } from '../entities/ips-signature.entity.js';
import { ZonePair } from '../entities/zone-pair.entity.js';
import { MlModel } from '../entities/ml-model.entity.js';
import { NatRule } from '../entities/nat-rule.entity.js';
import { Zone } from '../entities/zone.entity.js';
import { User } from '../entities/user.entity.js';

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
