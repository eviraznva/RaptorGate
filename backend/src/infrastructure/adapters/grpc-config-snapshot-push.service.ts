import { randomUUID } from "node:crypto";
import {
  Inject,
  Injectable,
  OnModuleInit,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { firstValueFrom } from "rxjs";
import type {
  ConfigSnapshotPushReason,
  IConfigSnapshotPushService,
} from "../../application/ports/config-snapshot-push-service.interface.js";
import type { ConfigurationSnapshot } from "../../domain/entities/configuration-snapshot.entity.js";
import type { ConfigSnapshotPayload } from "../../domain/value-objects/config-snapshot-payload.interface.js";
import {
  CertificateType,
  DefaultPolicy,
  NatRuleType,
  Severity,
} from "../grpc/generated/common/common.js";
import type { Timestamp } from "../grpc/generated/google/protobuf/timestamp.js";
import {
  type ConfigBundle,
  FIREWALL_CONFIG_SNAPSHOT_SERVICE_NAME,
  type FirewallConfigSnapshotServiceClient,
  type PushActiveConfigSnapshotRequest,
} from "../grpc/generated/services/config_snapshot_service.js";

export const CONFIG_SNAPSHOT_PUSH_GRPC_CLIENT_TOKEN =
  "CONFIG_SNAPSHOT_PUSH_GRPC_CLIENT_TOKEN";

@Injectable()
export class GrpcConfigSnapshotPushService
  implements IConfigSnapshotPushService, OnModuleInit
{
  private configSnapshotPushClient: FirewallConfigSnapshotServiceClient;

  constructor(
    @Inject(CONFIG_SNAPSHOT_PUSH_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.configSnapshotPushClient =
      this.grpcClient.getService<FirewallConfigSnapshotServiceClient>(
        FIREWALL_CONFIG_SNAPSHOT_SERVICE_NAME,
      );
  }

  async pushActiveConfigSnapshot(
    snapshot: ConfigurationSnapshot,
    reason: ConfigSnapshotPushReason,
  ): Promise<void> {
    const payload = snapshot.deserializePayload();

    const request: PushActiveConfigSnapshotRequest = {
      correlationId: randomUUID(),
      reason,
      snapshot: {
        id: snapshot.getId(),
        versionNumber: snapshot.getVersionNumber(),
        snapshotType: snapshot.getSnapshotType().getValue(),
        checksum: snapshot.getChecksum().getValue(),
        isActive: snapshot.getIsActive(),
        changesSummary: snapshot.getChangesSummary() ?? "",
        createdAt: this.toTimestamp(snapshot.getCreatedAt()),
        createdBy: snapshot.getCreatedBy(),
        bundle: this.toBundle(payload),
      },
    };

    try {
      const response = await firstValueFrom(
        this.configSnapshotPushClient.pushActiveConfigSnapshot(request),
      );

      if (!response.accepted) {
        throw new Error(
          `Firewall rejected active snapshot push: ${response.message || "unknown reason"}`,
        );
      }
    } catch (error) {
      const reasonText =
        error instanceof Error ? error.message : "Unknown gRPC error";

      throw new ServiceUnavailableException(
        `Firewall config snapshot push service is unavailable. ${reasonText}`,
      );
    }
  }

  private toBundle(payload: ConfigSnapshotPayload): ConfigBundle {
    const b = payload.bundle;

    return {
      rules: b.rules.items.map((r) => ({
        id: r.getId(),
        name: r.getName(),
        zonePairId: r.getZonePairId(),
        priority: r.getPriority().getValue(),
        content: r.getContent(),
      })),
      zones: b.zones.items.map((z) => ({
        id: z.getId(),
        name: z.getName(),
        interfaceIds: [],
      })),
      zoneInterfaces: b.zone_interfaces.items.map((zi) => ({
        id: zi.getId(),
        zoneId: "",
        interfaceName: zi.getInterfaceName(),
        vlanId: zi.getVlanId(),
      })),
      zonePairs: b.zone_pairs.items.map((zp) => ({
        id: zp.getId(),
        srcZoneId: zp.getSrcZoneId(),
        dstZoneId: zp.getDstZoneId(),
        defaultPolicy: this.toDefaultPolicy(zp.getDefaultPolicy()),
      })),
      natRules: b.nat_rules.items.map((n) => ({
        id: n.getId(),
        type: this.toNatRuleType(n.getType().getValue()),
        srcIp: n.getSourceIp()?.getValue ?? "",
        dstIp: n.getDestinationIp()?.getValue ?? "",
        srcPort: n.getSourcePort()?.getValue,
        dstPort: n.getDestinationPort()?.getValue,
        translatedIp: n.getTranslatedIp()?.getValue ?? "",
        translatedPort: n.getTranslatedPort()?.getValue,
        priority: n.getPriority().getValue(),
      })),
      dnsBlacklist: b.dns_blacklist.items.map((d) => ({
        id: d.getId(),
        domain: d.getDomain(),
      })),
      sslBypassList: b.ssl_bypass_list.items.map((s) => ({
        id: s.getId(),
        domain: s.getDomain(),
      })),
      ipsSignatures: b.ips_signatures.items.map((i) => ({
        id: i.getId(),
        name: i.getName(),
        category: i.getCategory().getValue(),
        pattern: i.getPattern().getValue(),
        severity: this.toSeverity(i.getSeverity()),
      })),
      mlModel: b.ml_model
        ? {
            id: b.ml_model.getId(),
            name: b.ml_model.getName(),
            artifactPath: b.ml_model.getArtifactPath(),
            checksum: b.ml_model.getChecksum().getValue(),
          }
        : undefined,
      firewallCertificates: b.firewall_certificates.items.map((c) => ({
        id: c.getId(),
        certType: this.toCertificateType(c.getCertType()),
        commonName: c.getCommonName(),
        fingerprint: c.getFingerprint(),
        certificatePem: c.getCertificatePem(),
        privateKeyRef: c.getPrivateKeyRef(),
        expiresAt: this.toTimestamp(c.getExpiresAt()),
      })),
      identity: undefined,
    };
  }

  private toTimestamp(date: Date): Timestamp {
    const ms = date.getTime();
    return {
      seconds: Math.floor(ms / 1000),
      nanos: (ms % 1000) * 1_000_000,
    };
  }

  private toDefaultPolicy(value: string): DefaultPolicy {
    switch (value.toUpperCase()) {
      case "ALLOW":
        return DefaultPolicy.DEFAULT_POLICY_ALLOW;
      case "DROP":
      case "DENY":
        return DefaultPolicy.DEFAULT_POLICY_DROP;
      default:
        return DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED;
    }
  }

  private toNatRuleType(value: string): NatRuleType {
    switch (value.toUpperCase()) {
      case "SNAT":
        return NatRuleType.NAT_RULE_TYPE_SNAT;
      case "DNAT":
        return NatRuleType.NAT_RULE_TYPE_DNAT;
      case "PAT":
        return NatRuleType.NAT_RULE_TYPE_PAT;
      default:
        return NatRuleType.NAT_RULE_TYPE_UNSPECIFIED;
    }
  }

  private toSeverity(value: string): Severity {
    switch (value.toUpperCase()) {
      case "LOW":
        return Severity.SEVERITY_LOW;
      case "MEDIUM":
        return Severity.SEVERITY_MEDIUM;
      case "HIGH":
        return Severity.SEVERITY_HIGH;
      case "CRITICAL":
        return Severity.SEVERITY_CRITICAL;
      case "INFO":
        return Severity.SEVERITY_INFO;
      default:
        return Severity.SEVERITY_UNSPECIFIED;
    }
  }

  private toCertificateType(value: string): CertificateType {
    switch (value.toUpperCase()) {
      case "CA":
        return CertificateType.CERTIFICATE_TYPE_CA;
      case "TLS_SERVER":
      case "TLS_SWERVER":
        return CertificateType.CERTIFICATE_TYPE_TLS_SERVER;
      default:
        return CertificateType.CERTIFICATE_TYPE_UNSPECIFIED;
    }
  }
}
