import {
  DefaultPolicy,
  NatRuleType,
  Severity,
  CertificateType,
  IdentitySource,
} from 'src/infrastructure/grpc/generated/common/common';
import { ConfigSnapshotPayload } from 'src/domain/value-objects/config-snapshot-payload.interface';
import { ConfigSectionVersions } from 'src/infrastructure/grpc/generated/config/config_models';
import { ConfigResponse } from 'src/infrastructure/grpc/generated/config/config_service';

function mapDefaultPolicy(v: string): DefaultPolicy {
  switch (v) {
    case 'ALLOW':
      return DefaultPolicy.DEFAULT_POLICY_ALLOW;
    case 'DROP':
      return DefaultPolicy.DEFAULT_POLICY_DROP;
    default:
      return DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED;
  }
}

function mapNatRuleType(v: string): NatRuleType {
  switch (v) {
    case 'SNAT':
      return NatRuleType.NAT_RULE_TYPE_SNAT;
    case 'DNAT':
      return NatRuleType.NAT_RULE_TYPE_DNAT;
    case 'PAT':
      return NatRuleType.NAT_RULE_TYPE_PAT;
    default:
      return NatRuleType.NAT_RULE_TYPE_UNSPECIFIED;
  }
}

function mapSeverity(v: string): Severity {
  switch (v) {
    case 'INFO':
      return Severity.SEVERITY_INFO;
    case 'LOW':
      return Severity.SEVERITY_LOW;
    case 'MEDIUM':
      return Severity.SEVERITY_MEDIUM;
    case 'HIGH':
      return Severity.SEVERITY_HIGH;
    case 'CRITICAL':
      return Severity.SEVERITY_CRITICAL;
    default:
      return Severity.SEVERITY_UNSPECIFIED;
  }
}

function mapCertificateType(v: string): CertificateType {
  switch (v) {
    case 'CA':
      return CertificateType.CERTIFICATE_TYPE_CA;
    case 'TLS_SERVER':
      return CertificateType.CERTIFICATE_TYPE_TLS_SERVER;
    default:
      return CertificateType.CERTIFICATE_TYPE_UNSPECIFIED;
  }
}

function mapIdentitySource(v: string): IdentitySource {
  switch (v) {
    case 'LOCAL':
      return IdentitySource.IDENTITY_SOURCE_LOCAL;
    case 'RADIUS':
      return IdentitySource.IDENTITY_SOURCE_RADIUS;
    case 'ACTIVE_DIRECTORY':
      return IdentitySource.IDENTITY_SOURCE_ACTIVE_DIRECTORY;
    default:
      return IdentitySource.IDENTITY_SOURCE_UNSPECIFIED;
  }
}

function isoToTimestamp(iso: string): { seconds: number; nanos: number } {
  const ms = new Date(iso).getTime();
  return {
    seconds: Math.floor(ms / 1000),
    nanos: (ms % 1000) * 1_000_000,
  };
}

// ── Główna funkcja mappera ────────────────────────────────────────────────────
export function mapPayloadToConfigResponse(
  payload: ConfigSnapshotPayload,
  correlationId: string,
  configVersion: number,
  bundleChecksum: string,
  knownVersions: ConfigSectionVersions | undefined,
): ConfigResponse {
  const sv = payload.section_versions;
  const b = payload.bundle;

  const send = (sectionVersion: number, known: number | undefined): boolean =>
    known === undefined || sectionVersion > known;

  const currentVersions: ConfigSectionVersions = {
    rules: sv.rules,
    zones: sv.zones,
    zoneInterfaces: sv.zone_interfaces,
    zonePairs: sv.zone_pairs,
    natRules: sv.nat_rules,
    dnsBlacklist: sv.dns_blacklist,
    sslBypassList: sv.ssl_bypass_list,
    ipsSignatures: sv.ips_signatures,
    mlModel: sv.ml_model,
    certificates: sv.certificates,
    identity: sv.identity,
  };

  const configurationChanged =
    !knownVersions ||
    Object.keys(currentVersions).some(
      (k) =>
        currentVersions[k as keyof ConfigSectionVersions] >
        (knownVersions[k as keyof ConfigSectionVersions] ?? 0),
    );

  return {
    configVersion,
    bundleChecksum,
    correlationId,
    configurationChanged,
    currentVersions,
    rules: send(sv.rules, knownVersions?.rules)
      ? {
          version: sv.rules,
          checksum: b.rules.checksum,
          items: b.rules.items.map((r) => ({
            id: r.id,
            name: r.name,
            zonePairId: r.zone_pair_id,
            priority: r.priority,
            content: r.content,
          })),
        }
      : undefined,
    zones: send(sv.zones, knownVersions?.zones)
      ? {
          version: sv.zones,
          items: b.zones.items.map((z) => ({ id: z.id, name: z.name })),
        }
      : undefined,
    zoneInterfaces: send(sv.zone_interfaces, knownVersions?.zoneInterfaces)
      ? {
          version: sv.zone_interfaces,
          items: b.zone_interfaces.items.map((zi) => ({
            id: zi.id,
            zoneId: zi.zone_id,
            interfaceName: zi.interface_name,
            vlanId: zi.vlan_id ?? undefined,
          })),
        }
      : undefined,
    zonePairs: send(sv.zone_pairs, knownVersions?.zonePairs)
      ? {
          version: sv.zone_pairs,
          items: b.zone_pairs.items.map((zp) => ({
            id: zp.id,
            srcZoneId: zp.src_zone_id,
            dstZoneId: zp.dst_zone_id,
            defaultPolicy: mapDefaultPolicy(zp.default_policy),
          })),
        }
      : undefined,
    natRules: send(sv.nat_rules, knownVersions?.natRules)
      ? {
          version: sv.nat_rules,
          items: b.nat_rules.items.map((n) => ({
            id: n.id,
            type: mapNatRuleType(n.type),
            srcIp: n.src_ip,
            dstIp: n.dst_ip,
            srcPort: n.src_port ?? undefined,
            dstPort: n.dst_port ?? undefined,
            translatedIp: n.translated_ip,
            translatedPort: n.translated_port ?? undefined,
            priority: n.priority,
          })),
        }
      : undefined,
    dnsBlacklist: send(sv.dns_blacklist, knownVersions?.dnsBlacklist)
      ? {
          version: sv.dns_blacklist,
          items: b.dns_blacklist.items.map((d) => ({
            id: d.id,
            domain: d.domain,
          })),
        }
      : undefined,
    sslBypassList: send(sv.ssl_bypass_list, knownVersions?.sslBypassList)
      ? {
          version: sv.ssl_bypass_list,
          items: b.ssl_bypass_list.items.map((s) => ({
            id: s.id,
            domain: s.domain,
          })),
        }
      : undefined,
    ipsSignatures: send(sv.ips_signatures, knownVersions?.ipsSignatures)
      ? {
          version: sv.ips_signatures,
          items: b.ips_signatures.items.map((i) => ({
            id: i.id,
            name: i.name,
            category: i.category,
            pattern: i.pattern,
            severity: mapSeverity(i.severity),
          })),
        }
      : undefined,
    mlModel: send(sv.ml_model, knownVersions?.mlModel)
      ? {
          version: sv.ml_model,
          id: b.ml_model.id,
          name: b.ml_model.name,
          artifactPath: b.ml_model.artifact_path,
          checksum: b.ml_model.checksum,
        }
      : undefined,
    firewallCertificates: send(sv.certificates, knownVersions?.certificates)
      ? {
          version: sv.certificates,
          items: b.firewall_certificates.items.map((c) => ({
            id: c.id,
            certType: mapCertificateType(c.cert_type),
            commonName: c.common_name,
            fingerprint: c.fingerprint,
            certificatePem: c.certificate_pem,
            privateKeyRef: c.private_key_ref,
            expiresAt: isoToTimestamp(c.expires_at),
          })),
        }
      : undefined,
    identity: send(sv.identity, knownVersions?.identity)
      ? {
          version: sv.identity,
          userGroups: b.identity.user_groups.map((g) => ({
            id: g.id,
            name: g.name,
            source: mapIdentitySource(g.source),
          })),
          identityUsers: b.identity.identity_users.map((u) => ({
            id: u.id,
            username: u.username,
            displayName: u.display_name,
            source: mapIdentitySource(u.source),
            externalId: u.external_id,
          })),
          userGroupMembers: b.identity.user_group_members.map((m) => ({
            id: m.id,
            groupId: m.group_id,
            identityUserId: m.identity_user_id,
          })),
          userSessions: b.identity.user_sessions.map((s) => ({
            id: s.id,
            identityUserId: s.identity_user_id,
            radiusUsername: s.radius_username,
            macAddress: s.mac_address,
            ipAddress: s.ip_address,
            nasIp: s.nas_ip,
            calledStationId: s.called_station_id,
            authenticatedAt: isoToTimestamp(s.authenticated_at),
            expiresAt: isoToTimestamp(s.expires_at),
          })),
        }
      : undefined,
  };
}
