import { randomUUID } from "node:crypto";
import {
  Inject,
  Injectable,
  Logger,
  OnModuleInit,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { firstValueFrom } from "rxjs";
import type {
  ConfigSnapshotPushReason,
  FactoryResetCommand,
  FactoryResetResult,
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
import {
  type DecryptionMirrorConfig,
  InterfaceStatus,
  type TlsInspectionPolicy,
} from "../grpc/generated/config/config_models.js";
import type { Timestamp } from "../grpc/generated/google/protobuf/timestamp.js";
import {
  type ConfigBundle,
  type FactoryResetRequest,
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
  private readonly logger = new Logger(GrpcConfigSnapshotPushService.name);
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

  async factoryReset(
    command: FactoryResetCommand,
  ): Promise<FactoryResetResult> {
    const correlationId = randomUUID();
    const request: FactoryResetRequest = {
      correlationId,
      reason: command.reason ?? "factory_reset",
      clearPki: command.clearPki,
      clearServerKeys: command.clearServerKeys,
    };

    this.logger.warn({
      event: "firewall.factory_reset.started",
      message: "requesting firewall factory reset",
      correlationId,
      clearPki: request.clearPki ?? true,
      clearServerKeys: request.clearServerKeys ?? true,
    });

    try {
      const response = await firstValueFrom(
        this.configSnapshotPushClient.factoryReset(request),
      );

      if (!response.accepted) {
        this.logger.warn({
          event: "firewall.factory_reset.rejected",
          message: response.message || "firewall rejected factory reset",
          correlationId,
          safeStateApplied: response.safeStateApplied,
        });
        throw new Error(
          `Firewall rejected factory reset: ${response.message || "unknown reason"}`,
        );
      }

      this.logger.warn({
        event: "firewall.factory_reset.succeeded",
        message: "firewall factory reset completed",
        correlationId,
        removedServerKeys: response.removedServerKeys,
        removedServerKeyFiles: response.removedServerKeyFiles,
        removedCaFiles: response.removedCaFiles,
      });

      return response;
    } catch (error) {
      const reasonText =
        error instanceof Error ? error.message : "Unknown gRPC error";

      this.logger.error(
        {
          event: "firewall.factory_reset.failed",
          message: "failed to request firewall factory reset",
          correlationId,
          error: reasonText,
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        `Firewall factory reset service is unavailable. ${reasonText}`,
      );
    }
  }

  async pushActiveConfigSnapshot(
    snapshot: ConfigurationSnapshot,
    reason: ConfigSnapshotPushReason,
  ): Promise<void> {
    const payload = snapshot.deserializePayload();
    const correlationId = randomUUID();

    const request: PushActiveConfigSnapshotRequest = {
      correlationId,
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

    this.logger.log({
      event: "firewall.snapshot.push.started",
      message: "pushing active config snapshot to firewall",
      correlationId,
      reason,
      snapshotId: snapshot.getId(),
      versionNumber: snapshot.getVersionNumber(),
      counts: bundleCounts(payload),
    });

    try {
      const response = await firstValueFrom(
        this.configSnapshotPushClient.pushActiveConfigSnapshot(request),
      );

      if (!response.accepted) {
        this.logger.warn({
          event: "firewall.snapshot.push.rejected",
          message: response.message || "firewall rejected active snapshot push",
          correlationId,
          reason,
          snapshotId: snapshot.getId(),
        });
        throw new Error(
          `Firewall rejected active snapshot push: ${response.message || "unknown reason"}`,
        );
      }

      this.logger.log({
        event: "firewall.snapshot.push.succeeded",
        message: "firewall accepted active config snapshot",
        correlationId,
        reason,
        snapshotId: snapshot.getId(),
        appliedSnapshotId: response.appliedSnapshotId,
      });
    } catch (error) {
      const reasonText =
        error instanceof Error ? error.message : "Unknown gRPC error";

      this.logger.error(
        {
          event: "firewall.snapshot.push.failed",
          message: "failed to push active config snapshot to firewall",
          correlationId,
          reason,
          snapshotId: snapshot.getId(),
          error: reasonText,
        },
        error instanceof Error ? error.stack : undefined,
      );

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
      })),
      zoneInterfaces: b.zone_interfaces.items.map((zi) => {
        const base = {
          id: zi.getId(),
          zoneId: zi.getZoneId(),
          status: this.toZoneInterfaceStatus(zi.getStatus()),
          addresses: zi.getAddresses(),
          sniffed: zi.getSniffed(),
        };
        return zi.getVlanId() == null
          ? { ...base, physical: { interfaceName: zi.getInterfaceName() } } as any
          : { ...base, vlan: { parentInterfaceId: zi.getParentInterfaceId() ?? "", vlanId: zi.getVlanId()! } } as any;
      }),
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
        severity: this.toSeverity(i.getSeverity().getValue()),
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
        bindAddress: c.getBindAddress(),
        bindPort: c.getBindPort(),
        inspectionBypass: c.getInspectionBypass(),
        isActive: c.getIsActive(),
      })),
      tlsInspectionPolicy: this.toTlsInspectionPolicy(b.tls_inspection_policy),
      identity: undefined,
    };
  }

  private toTlsInspectionPolicy(
    policy: ConfigSnapshotPayload["bundle"]["tls_inspection_policy"],
  ): TlsInspectionPolicy {
    return {
      blockEchNoSni: policy?.block_ech_no_sni ?? true,
      blockAllEch: policy?.block_all_ech ?? false,
      stripEchDns: policy?.strip_ech_dns ?? true,
      logEchAttempts: policy?.log_ech_attempts ?? true,
      knownPinnedDomains: [...(policy?.known_pinned_domains ?? [])],
      decryptionMirror: this.toDecryptionMirrorConfig(policy?.decryption_mirror),
    };
  }

  private toDecryptionMirrorConfig(
    config: NonNullable<ConfigSnapshotPayload["bundle"]["tls_inspection_policy"]>["decryption_mirror"] | undefined,
  ): DecryptionMirrorConfig {
    return {
      enabled: config?.enabled ?? false,
      targetHost: config?.target_host ?? "",
      targetPort: config?.target_port ?? 0,
      includeClientToServer: config?.include_client_to_server ?? true,
      includeServerToClient: config?.include_server_to_client ?? true,
      forwardedOnly: config?.forwarded_only ?? true,
      maxSessionBytes: config?.max_session_bytes ?? 16 * 1024 * 1024,
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

  private toZoneInterfaceStatus(value: string): InterfaceStatus {
    switch (value.toUpperCase()) {
      case "ACTIVE":
        return InterfaceStatus.INTERFACE_STATUS_ACTIVE;
      case "INACTIVE":
        return InterfaceStatus.INTERFACE_STATUS_INACTIVE;
      case "MISSING":
        return InterfaceStatus.INTERFACE_STATUS_MISSING;
      case "UNKNOWN":
        return InterfaceStatus.INTERFACE_STATUS_UNKNOWN;
      case "UNSPECIFIED":
      default:
        return InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED;
    }
  }
}

function bundleCounts(payload: ConfigSnapshotPayload) {
  const bundle = payload.bundle;

  return {
    rules: bundle.rules.items.length,
    zones: bundle.zones.items.length,
    zonePairs: bundle.zone_pairs.items.length,
    natRules: bundle.nat_rules.items.length,
    dnsBlacklist: bundle.dns_blacklist.items.length,
    ipsSignatures: bundle.ips_signatures.items.length,
  };
}
