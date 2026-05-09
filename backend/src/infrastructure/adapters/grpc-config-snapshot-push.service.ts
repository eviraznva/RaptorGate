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
import type {
  DnssecFailureAction,
  DnssecTransport,
  DnsInspectionConfig as DomainDnsInspectionConfig,
} from "../../domain/entities/dns-inspection-config.entity.js";
import type { IpsConfig as DomainIpsConfig } from "../../domain/entities/ips-config.entity.js";
import type {
  NatRule as DomainNatRule,
  NatRuleAction,
} from "../../domain/entities/nat-rule.entity.js";
import { NatConfigIsInvalidException } from "../../domain/exceptions/nat-config-is-invalid.exception.js";
import type { ConfigSnapshotPayload } from "../../domain/value-objects/config-snapshot-payload.interface.js";
import {
  CertificateType,
  DefaultPolicy,
  Severity,
} from "../grpc/generated/common/common.js";
import {
  DnsInspectionDnssecFailureAction,
  DnsInspectionDnssecTransport,
  InterfaceStatus,
  IpsAction,
  IpsAppProtocol,
  IpsMatchType,
  IpsPatternEncoding,
  type DnsInspectionConfig as ProtoDnsInspectionConfig,
  type IpsConfig as ProtoIpsConfig,
  type NatRule as ProtoNatRule,
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
        payload: request.snapshot?.bundle,
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
          payload: request.snapshot?.bundle,
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
      zoneInterfaces: b.zone_interfaces.items.map((zi) => ({
        id: zi.getId(),
        zoneId: zi.getZoneId(),
        status: this.toZoneInterfaceStatus(zi.getStatus()),
        addresses: zi.getAddresses(),
        ...(zi.getVlanId() === null
          ? { physical: { interfaceName: zi.getInterfaceName() } }
          : {
              vlan: {
                parentInterfaceId: zi.getInterfaceName(),
                vlanId: zi.getVlanId() ?? 0,
              },
            }),
        sniffed: zi.getSniffed(),
      })) as any,
      zonePairs: b.zone_pairs.items.map((zp) => ({
        id: zp.getId(),
        srcZoneId: zp.getSrcZoneId(),
        dstZoneId: zp.getDstZoneId(),
        defaultPolicy: this.toDefaultPolicy(zp.getDefaultPolicy()),
      })),
      natRules: b.nat_rules.items.map((n) => this.toNatRule(n)) as any,
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
      dnsInspectionConfig: b.dns_inspection_config
        ? this.toDnsInspectionConfig(b.dns_inspection_config)
        : undefined,
      ipsConfig: b.ips_config ? this.toIpsConfig(b.ips_config) : undefined,
      identity: undefined,
    };
  }

  private toNatRule(n: DomainNatRule): Record<string, unknown> {
    const action = n.getAction();
    const normalized = this.normalizeActionShape(action);

    if (!normalized?.$case) {
      throw new NatConfigIsInvalidException(
        "unknown",
        "action",
        "action is required",
      );
    }

    return {
      id: n.getId(),
      priority: n.getPriority().getValue(),
      inInterface: n.getInInterface() ?? undefined,
      outInterface: n.getOutInterface() ?? undefined,
      inZone: n.getInZone() ?? undefined,
      outZone: n.getOutZone() ?? undefined,
      protocol: n.getProtocol(),
      matchSrcPortMin: n.getMatchSrcPortMin()?.getValue,
      matchSrcPortMax: n.getMatchSrcPortMax()?.getValue,
      matchDstPortMin: n.getMatchDstPortMin()?.getValue,
      matchDstPortMax: n.getMatchDstPortMax()?.getValue,
      ...this.toFlatNatAction(normalized),
    };
  }

  private toFlatNatAction(
    action: NatRuleAction,
  ): Record<string, unknown> {
    switch (action.$case) {
      case "snat":
        return {
          snat: {
            srcCidr: action.snat.srcCidr,
            translatedIp: action.snat.translatedIp,
            srcPortMin: action.snat.srcPortMin?.getValue,
            srcPortMax: action.snat.srcPortMax?.getValue,
          },
        };
      case "dnat":
        return {
          dnat: {
            dstCidr: action.dnat.dstCidr,
            translatedIp: action.dnat.translatedIp,
            translatedPort: action.dnat.translatedPort?.getValue,
          },
        };
      case "pat":
        return {
          pat: {
            dstIp: action.pat.dstIp,
            dstPort: action.pat.dstPort.getValue,
            translatedIp: action.pat.translatedIp,
            translatedPort: action.pat.translatedPort.getValue,
          },
        };
      case "masquerade":
        return {
          masquerade: {
            srcCidr: action.masquerade.srcCidr,
            srcPortMin: action.masquerade.srcPortMin?.getValue,
            srcPortMax: action.masquerade.srcPortMax?.getValue,
          },
        };
      default:
        throw new NatConfigIsInvalidException(
          (action as { $case: string }).$case,
          "action",
          "unsupported action case",
        );
    }
  }

  private normalizeActionShape(action: NatRuleAction | undefined): NatRuleAction | undefined {
    if (!action) return undefined;

    if ("$case" in action) {
      return action;
    }

    const keys = Object.keys(action);
    if (keys.length !== 1) {
      return undefined;
    }

    const variant = keys[0];
    if (!["snat", "dnat", "pat", "masquerade"].includes(variant)) {
      return undefined;
    }

    return {
      $case: variant as any,
      [variant]: (action as any)[variant],
    } as NatRuleAction;
  }

  private toDnsInspectionConfig(
    config: DomainDnsInspectionConfig,
  ): ProtoDnsInspectionConfig {
    const general = config.getGeneral();
    const blocklist = config.getBlocklist();
    const dnsTunneling = config.getDnsTunneling();
    const dnssec = config.getDnssec();

    return {
      general: { enabled: general.enabled },
      blocklist: {
        enabled: blocklist.enabled,
        domains: [...blocklist.domains],
      },
      dnsTunneling: {
        enabled: dnsTunneling.enabled,
        maxLabelLength: dnsTunneling.maxLabelLength,
        entropyThreshold: dnsTunneling.entropyThreshold,
        windowSeconds: dnsTunneling.windowSeconds,
        maxQueriesPerDomain: dnsTunneling.maxQueriesPerDomain,
        maxUniqueSubdomains: dnsTunneling.maxUniqueSubdomains,
        ignoreDomains: [...dnsTunneling.ignoreDomains],
        alertThreshold: dnsTunneling.alertThreshold,
        blockThreshold: dnsTunneling.blockThreshold,
      },
      dnssec: {
        enabled: dnssec.enabled,
        maxLookupsPerPacket: dnssec.maxLookupsPerPacket,
        defaultOnResolverFailure: this.toDnssecFailureAction(
          dnssec.defaultOnResolverFailure,
        ),
        resolver: {
          primary: {
            address: dnssec.resolver.primary.address?.getValue ?? "",
            port: dnssec.resolver.primary.port.getValue,
          },
          secondary: {
            address: dnssec.resolver.secondary.address?.getValue ?? "",
            port: dnssec.resolver.secondary.port.getValue,
          },
          transport: this.toDnssecTransport(dnssec.resolver.transport),
          timeoutMs: dnssec.resolver.timeoutMs,
          retries: dnssec.resolver.retries,
        },
        cache: {
          enabled: dnssec.cache.enabled,
          maxEntries: dnssec.cache.maxEntries,
          ttlSeconds: {
            secure: dnssec.cache.ttlSeconds.secure,
            insecure: dnssec.cache.ttlSeconds.insecure,
            bogus: dnssec.cache.ttlSeconds.bogus,
            failure: dnssec.cache.ttlSeconds.failure,
          },
        },
      },
    };
  }

  private toIpsConfig(config: DomainIpsConfig): ProtoIpsConfig {
    return {
      general: config.getGeneral(),
      detection: config.getDetection(),
      signatures: config.getSignatures().map((signature) => ({
        id: signature.getId(),
        name: signature.getName(),
        enabled: signature.getIsActive(),
        category: signature.getCategory().getValue(),
        pattern: signature.getPattern().getValue(),
        severity: this.toIpsSeverity(signature.getSeverity().getValue()),
        action: this.toIpsAction(signature.getAction().getValue()),
        appProtocols: signature
          .getAppProtocols()
          .map((protocol) => this.toIpsAppProtocol(protocol.getValue())),
        srcPorts: signature.getSrcPorts().map((port) => port.getValue),
        dstPorts: signature.getDstPorts().map((port) => port.getValue),
        matchType: this.toIpsMatchType(signature.getMatchType().getValue()),
        patternEncoding: this.toIpsPatternEncoding(
          signature.getPatternEncoding().getValue(),
        ),
        caseInsensitive: signature.getCaseInsensitive(),
      })),
    };
  }

  private toIpsSeverity(value: string): Severity {
    const mapped = Severity[value as keyof typeof Severity];
    return typeof mapped === "number" ? mapped : Severity.SEVERITY_UNSPECIFIED;
  }

  private toIpsAction(value: string): IpsAction {
    const mapped = IpsAction[value as keyof typeof IpsAction];
    return typeof mapped === "number"
      ? mapped
      : IpsAction.IPS_ACTION_UNSPECIFIED;
  }

  private toIpsAppProtocol(value: string): IpsAppProtocol {
    const mapped = IpsAppProtocol[value as keyof typeof IpsAppProtocol];
    return typeof mapped === "number"
      ? mapped
      : IpsAppProtocol.IPS_APP_PROTOCOL_UNSPECIFIED;
  }

  private toIpsMatchType(value: string): IpsMatchType {
    const mapped = IpsMatchType[value as keyof typeof IpsMatchType];
    return typeof mapped === "number"
      ? mapped
      : IpsMatchType.IPS_MATCH_TYPE_UNSPECIFIED;
  }

  private toIpsPatternEncoding(value: string): IpsPatternEncoding {
    const mapped = IpsPatternEncoding[value as keyof typeof IpsPatternEncoding];
    return typeof mapped === "number"
      ? mapped
      : IpsPatternEncoding.IPS_PATTERN_ENCODING_UNSPECIFIED;
  }

  private toDnssecTransport(
    value: DnssecTransport,
  ): DnsInspectionDnssecTransport {
    switch (value) {
      case "udp":
        return DnsInspectionDnssecTransport.DNS_INSPECTION_DNSSEC_TRANSPORT_UDP;
      case "tcp":
        return DnsInspectionDnssecTransport.DNS_INSPECTION_DNSSEC_TRANSPORT_TCP;
      case "udpWithTcpFallback":
        return DnsInspectionDnssecTransport.DNS_INSPECTION_DNSSEC_TRANSPORT_UDP_WITH_TCP_FALLBACK;
    }
  }

  private toDnssecFailureAction(
    value: DnssecFailureAction,
  ): DnsInspectionDnssecFailureAction {
    switch (value) {
      case "allow":
        return DnsInspectionDnssecFailureAction.DNS_INSPECTION_DNSSEC_FAILURE_ACTION_ALLOW;
      case "alert":
        return DnsInspectionDnssecFailureAction.DNS_INSPECTION_DNSSEC_FAILURE_ACTION_ALERT;
      case "block":
        return DnsInspectionDnssecFailureAction.DNS_INSPECTION_DNSSEC_FAILURE_ACTION_BLOCK;
    }
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
