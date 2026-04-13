import { DnsInspectionConfig } from "../../domain/entities/dns-inspection-config.entity.js";
import { DnsInspectionConfigResponseDto } from "../dtos/dns-inspection-config-response.dto.js";

export class DnsInspectionResponseMapper {
  static toDto(config: DnsInspectionConfig): DnsInspectionConfigResponseDto {
    const dnssec = config.getDnssec();

    return {
      general: config.getGeneral(),
      blocklist: config.getBlocklist(),
      dnsTunneling: config.getDnsTunneling(),
      dnssec: {
        enabled: dnssec.enabled,
        maxLookupsPerPacket: dnssec.maxLookupsPerPacket,
        defaultOnResolverFailure: dnssec.defaultOnResolverFailure,
        resolver: {
          primary: {
            address: dnssec.resolver.primary.address?.getValue ?? "",
            port: dnssec.resolver.primary.port.getValue,
          },
          secondary: {
            address: dnssec.resolver.secondary.address?.getValue ?? "",
            port: dnssec.resolver.secondary.port.getValue,
          },
          transport: dnssec.resolver.transport,
          timeoutMs: dnssec.resolver.timeoutMs,
          retries: dnssec.resolver.retries,
        },
        cache: {
          enabled: dnssec.cache.enabled,
          maxEntries: dnssec.cache.maxEntries,
          ttlSeconds: dnssec.cache.ttlSeconds,
        },
      },
    };
  }
}
