import {
  Inject,
  Injectable,
  Logger,
  OnModuleInit,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { firstValueFrom } from "rxjs";
import type { IFirewallDnsInspectionQueryService } from "../../application/ports/firewall-dns-inspection-query-service.interface.js";
import {
  DnsInspectionConfig,
  type DnssecFailureAction,
  type DnssecTransport,
} from "../../domain/entities/dns-inspection-config.entity.js";
import { IpAddress } from "../../domain/value-objects/ip-address.vo.js";
import { Port } from "../../domain/value-objects/port.vo.js";
import {
  DnsInspectionDnssecFailureAction,
  DnsInspectionDnssecTransport,
  DnsInspectionConfig as GrpcDnsInspectionConfig,
} from "../grpc/generated/config/config_models.js";
import {
  FIREWALL_QUERY_SERVICE_NAME,
  type FirewallQueryServiceClient,
} from "../grpc/generated/services/query_service.js";

export const FIREWALL_QUERY_GRPC_CLIENT_TOKEN =
  "FIREWALL_QUERY_GRPC_CLIENT_TOKEN";

@Injectable()
export class GrpcFirewallDnsInspectionQueryService
  implements IFirewallDnsInspectionQueryService, OnModuleInit
{
  private readonly logger = new Logger(GrpcFirewallDnsInspectionQueryService.name);
  private firewallQueryClient: FirewallQueryServiceClient;

  constructor(
    @Inject(FIREWALL_QUERY_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.firewallQueryClient =
      this.grpcClient.getService<FirewallQueryServiceClient>(
        FIREWALL_QUERY_SERVICE_NAME,
      );
  }

  async swapDnsInspectionConfig(config: DnsInspectionConfig): Promise<void> {
    try {
      this.logger.log({
        event: "firewall.dns_inspection.swap.started",
        message: "swapping DNS inspection config on firewall",
        enabled: config.getGeneral().enabled,
        blocklistDomains: config.getBlocklist().domains.length,
        dnsTunnelingEnabled: config.getDnsTunneling().enabled,
        dnssecEnabled: config.getDnssec().enabled,
      });

      await firstValueFrom(
        this.firewallQueryClient.swapDnsInspectionConfig({
          config: this.toProto(config),
        }),
      );

      this.logger.log({
        event: "firewall.dns_inspection.swap.succeeded",
        message: "DNS inspection config swapped on firewall",
        enabled: config.getGeneral().enabled,
      });
    } catch (error) {
      this.logger.error(
        {
          event: "firewall.dns_inspection.swap.failed",
          message: "failed to swap DNS inspection config on firewall",
          error: error instanceof Error ? error.message : "Unknown gRPC error",
        },
        error instanceof Error ? error.stack : undefined,
      );
      throw this.toTransportException("swap DNS inspection config", error);
    }
  }

  async getDnsInspectionConfig(): Promise<DnsInspectionConfig> {
    try {
      this.logger.log({
        event: "firewall.dns_inspection.get.started",
        message: "loading DNS inspection config from firewall",
      });

      const response = await firstValueFrom(
        this.firewallQueryClient.getDnsInspectionConfig({}),
      );

      if (!response.config) {
        throw new ServiceUnavailableException(
          "Firewall query service returned empty DNS inspection config.",
        );
      }

      const config = this.toDomain(response.config);

      this.logger.log({
        event: "firewall.dns_inspection.get.succeeded",
        message: "loaded DNS inspection config from firewall",
        enabled: config.getGeneral().enabled,
        blocklistDomains: config.getBlocklist().domains.length,
      });

      return config;
    } catch (error) {
      if (error instanceof ServiceUnavailableException) {
        throw error;
      }

      this.logger.error(
        {
          event: "firewall.dns_inspection.get.failed",
          message: "failed to load DNS inspection config from firewall",
          error: error instanceof Error ? error.message : "Unknown gRPC error",
        },
        error instanceof Error ? error.stack : undefined,
      );
      throw this.toTransportException("get DNS inspection config", error);
    }
  }

  private toTransportException(
    action: string,
    error: unknown,
  ): ServiceUnavailableException {
    const reason =
      error instanceof Error ? error.message : "Unknown gRPC error";

    return new ServiceUnavailableException(
      `Firewall query service failed to ${action}. ${reason}`,
    );
  }

  private toProto(config: DnsInspectionConfig): GrpcDnsInspectionConfig {
    const general = config.getGeneral();
    const blocklist = config.getBlocklist();
    const dnsTunneling = config.getDnsTunneling();
    const dnssec = config.getDnssec();

    return {
      general: {
        enabled: general.enabled,
      },
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
        defaultOnResolverFailure: this.toProtoFailureAction(
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
          transport: this.toProtoTransport(dnssec.resolver.transport),
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

  private toDomain(config: GrpcDnsInspectionConfig): DnsInspectionConfig {
    if (
      !config.general ||
      !config.blocklist ||
      !config.dnsTunneling ||
      !config.dnssec ||
      !config.dnssec.resolver ||
      !config.dnssec.resolver.primary ||
      !config.dnssec.resolver.secondary ||
      !config.dnssec.cache ||
      !config.dnssec.cache.ttlSeconds
    ) {
      throw new ServiceUnavailableException(
        "Firewall query service returned incomplete DNS inspection config.",
      );
    }

    return DnsInspectionConfig.create(
      {
        enabled: config.general.enabled,
      },
      {
        enabled: config.blocklist.enabled,
        domains: [...config.blocklist.domains],
      },
      {
        enabled: config.dnsTunneling.enabled,
        maxLabelLength: config.dnsTunneling.maxLabelLength,
        entropyThreshold: config.dnsTunneling.entropyThreshold,
        windowSeconds: config.dnsTunneling.windowSeconds,
        maxQueriesPerDomain: config.dnsTunneling.maxQueriesPerDomain,
        maxUniqueSubdomains: config.dnsTunneling.maxUniqueSubdomains,
        ignoreDomains: [...config.dnsTunneling.ignoreDomains],
        alertThreshold: config.dnsTunneling.alertThreshold,
        blockThreshold: config.dnsTunneling.blockThreshold,
      },
      {
        enabled: config.dnssec.enabled,
        maxLookupsPerPacket: config.dnssec.maxLookupsPerPacket,
        defaultOnResolverFailure: this.fromProtoFailureAction(
          config.dnssec.defaultOnResolverFailure,
        ),
        resolver: {
          primary: {
            address: IpAddress.create(config.dnssec.resolver.primary.address),
            port: Port.create(config.dnssec.resolver.primary.port),
          },
          secondary: {
            address: config.dnssec.resolver.secondary.address
              ? IpAddress.create(config.dnssec.resolver.secondary.address)
              : null,
            port: Port.create(config.dnssec.resolver.secondary.port),
          },
          transport: this.fromProtoTransport(config.dnssec.resolver.transport),
          timeoutMs: config.dnssec.resolver.timeoutMs,
          retries: config.dnssec.resolver.retries,
        },
        cache: {
          enabled: config.dnssec.cache.enabled,
          maxEntries: config.dnssec.cache.maxEntries,
          ttlSeconds: {
            secure: config.dnssec.cache.ttlSeconds.secure,
            insecure: config.dnssec.cache.ttlSeconds.insecure,
            bogus: config.dnssec.cache.ttlSeconds.bogus,
            failure: config.dnssec.cache.ttlSeconds.failure,
          },
        },
      },
    );
  }

  private toProtoTransport(
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

  private fromProtoTransport(
    value: DnsInspectionDnssecTransport,
  ): DnssecTransport {
    switch (value) {
      case DnsInspectionDnssecTransport.DNS_INSPECTION_DNSSEC_TRANSPORT_UDP:
        return "udp";
      case DnsInspectionDnssecTransport.DNS_INSPECTION_DNSSEC_TRANSPORT_TCP:
        return "tcp";
      case DnsInspectionDnssecTransport.DNS_INSPECTION_DNSSEC_TRANSPORT_UDP_WITH_TCP_FALLBACK:
        return "udpWithTcpFallback";
      default:
        throw new ServiceUnavailableException(
          "Firewall query service returned unsupported DNSSEC transport.",
        );
    }
  }

  private toProtoFailureAction(
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

  private fromProtoFailureAction(
    value: DnsInspectionDnssecFailureAction,
  ): DnssecFailureAction {
    switch (value) {
      case DnsInspectionDnssecFailureAction.DNS_INSPECTION_DNSSEC_FAILURE_ACTION_ALLOW:
        return "allow";
      case DnsInspectionDnssecFailureAction.DNS_INSPECTION_DNSSEC_FAILURE_ACTION_ALERT:
        return "alert";
      case DnsInspectionDnssecFailureAction.DNS_INSPECTION_DNSSEC_FAILURE_ACTION_BLOCK:
        return "block";
      default:
        throw new ServiceUnavailableException(
          "Firewall query service returned unsupported DNSSEC failure action.",
        );
    }
  }
}
