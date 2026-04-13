import { ConfigurationSnapshot } from 'src/domain/entities/configuration-snapshot.entity';
import {
  ConfigSnapshotPayload,
  type TlsInspectionPolicyPayload,
  normalizeTlsInspectionPolicy,
} from 'src/domain/value-objects/config-snapshot-payload.interface';
import { DnsBlacklistFile } from '../schemas/dns-blacklist.schema';
import { FirewallCertificatesFile } from '../schemas/firewall-certificates.schema';
import { IpsSignaturesFile } from '../schemas/ips-signatures.schema';
import { NatRulesFile } from '../schemas/nat-rules.schema';
import { RulesFile } from '../schemas/rules.schema';
import { SslBypassListFile } from '../schemas/ssl-bypass-list.schema';
import { UsersFile } from '../schemas/users.schema';
import { ZoneInterfacesFile } from '../schemas/zone-interfaces.schema';
import { ZonePairsFile } from '../schemas/zone-pairs.schema';
import { ZonesFile } from '../schemas/zones.schema';
import { FirewallCertificateJsonMapper } from './firewall-certificate-json.mapper';
import { NatRuleJsonMapper } from './nat-rule-json.mapper';
import { RuleJsonMapper } from './rule-json.mapper';
import { SslBypassJsonMapper } from './ssl-bypass-json.mapper';
import { UserJsonMapper } from './user-json.mapper';
import { ZoneJsonMapper } from './zone-json.mapper';
import { ZonePairJsonMapper } from './zone-pair-json.mapper';

export interface ConfigBundlePayloadSchema {
  rules: RulesFile;
  zones: ZonesFile;
  zone_interfaces: ZoneInterfacesFile;
  zone_pairs: ZonePairsFile;
  nat_rules: NatRulesFile;
  dns_blacklist: DnsBlacklistFile;
  ssl_bypass_list: SslBypassListFile;
  ips_signatures: IpsSignaturesFile;
  ml_model: null;
  firewall_certificates: FirewallCertificatesFile;
  tls_inspection_policy?: TlsInspectionPolicyPayload;
  users: UsersFile;
  // roles: RolesFile;
  // permissions: PermissionsFile;
  // role_permissions: RolePermissionsFile;
  // user_roles: UserRolesFile;
}

export interface ConfigSnapshotPayloadSchema {
  bundle: ConfigBundlePayloadSchema;
}

export function mapConfigSnapshotToPayloadRecord(
  configSnapshot: ConfigurationSnapshot,
): ConfigSnapshotPayloadSchema {
  const payload = configSnapshot.deserializePayload();

  const toNatRulesFile = payload.bundle.nat_rules.items.map((natRule) =>
    NatRuleJsonMapper.toRecord(natRule, crypto.randomUUID()),
  );

  const toRulesFile = payload.bundle.rules.items.map((rule) =>
    RuleJsonMapper.toRecord(rule),
  );

  const toZonePairFile = payload.bundle.zone_pairs.items.map((zonePair) =>
    ZonePairJsonMapper.toRecord(zonePair),
  );

  const toZonesFile = payload.bundle.zones.items.map((zone) =>
    ZoneJsonMapper.toRecord(zone, crypto.randomUUID()),
  );

  const toUsersFile = payload.bundle.users.items.map((user) =>
    UserJsonMapper.toRecord(user),
  );

  const toSslBypassFile = payload.bundle.ssl_bypass_list.items.map((entry) =>
    SslBypassJsonMapper.toRecord(entry, crypto.randomUUID()),
  );

  const toCertsFile = payload.bundle.firewall_certificates.items.map((cert) =>
    FirewallCertificateJsonMapper.toRecord(cert, crypto.randomUUID()),
  );

  return {
    bundle: {
      rules: {
        items: toRulesFile,
      },
      zones: {
        items: toZonesFile,
      },
      zone_interfaces: {
        items: [],
      },
      zone_pairs: {
        items: toZonePairFile,
      },
      nat_rules: {
        items: toNatRulesFile,
      },
      dns_blacklist: {
        items: [],
      },
      ssl_bypass_list: {
        items: toSslBypassFile,
      },
      ips_signatures: {
        items: [],
      },
      ml_model: null,
      firewall_certificates: {
        items: toCertsFile,
      },
      tls_inspection_policy: normalizeTlsInspectionPolicy(
        payload.bundle.tls_inspection_policy,
      ),
      users: {
        items: toUsersFile,
      },
    },
  };
}

export function mapConfigBundlePayloadToDomain(
  configurationSnapshot: ConfigurationSnapshot,
): ConfigSnapshotPayload {
  const payloadRaw: unknown = configurationSnapshot.getPayloadJson();
  const payload = JSON.parse(
    payloadRaw as string,
  ) as ConfigSnapshotPayloadSchema;

  const toRulesDomain = payload.bundle.rules.items.map((rule) =>
    RuleJsonMapper.toDomain(rule),
  );

  const toNatRulesDomain = payload.bundle.nat_rules.items.map((natRule) =>
    NatRuleJsonMapper.toDomain(natRule),
  );

  const toZonePairDomain = payload.bundle.zone_pairs.items.map((zonePair) =>
    ZonePairJsonMapper.toDomain(zonePair),
  );

  const toZonesDomain = payload.bundle.zones.items.map((zone) =>
    ZoneJsonMapper.toDomain(zone),
  );

  const toUsersDomain = payload.bundle.users.items.map((user) =>
    UserJsonMapper.toDomain(user),
  );

  const toSslBypassDomain = payload.bundle.ssl_bypass_list.items.map((entry) =>
    SslBypassJsonMapper.toDomain(entry),
  );

  const toCertsDomain = payload.bundle.firewall_certificates.items.map(
    (cert) => FirewallCertificateJsonMapper.toDomain(cert),
  );

  return {
    bundle: {
      rules: {
        items: toRulesDomain,
      },
      zones: {
        items: toZonesDomain,
      },
      zone_interfaces: {
        items: [],
      },
      zone_pairs: {
        items: toZonePairDomain,
      },
      nat_rules: {
        items: toNatRulesDomain,
      },
      dns_blacklist: {
        items: [],
      },
      ssl_bypass_list: {
        items: toSslBypassDomain,
      },
      ips_signatures: {
        items: [],
      },
      ml_model: null,
      firewall_certificates: {
        items: toCertsDomain,
      },
      tls_inspection_policy: normalizeTlsInspectionPolicy(
        payload.bundle.tls_inspection_policy,
      ),
      users: {
        items: toUsersDomain,
      },
    },
  };
}
