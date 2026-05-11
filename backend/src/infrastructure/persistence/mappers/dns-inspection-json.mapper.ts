import { DnsInspectionConfig } from "../../../domain/entities/dns-inspection-config.entity.js";
import { IpAddress } from "../../../domain/value-objects/ip-address.vo.js";
import { Port } from "../../../domain/value-objects/port.vo.js";
import { DnsInspectionRecord } from "../schemas/dns-inspection.schema.js";

export class DnsInspectionJsonMapper {
  static toDomain(record: DnsInspectionRecord): DnsInspectionConfig {
    return DnsInspectionConfig.create(
      record.general,
      record.blocklist,
      record.dnsTunneling,
      {
        enabled: record.dnssec.enabled,
        maxLookupsPerPacket: record.dnssec.maxLookupsPerPacket,
        defaultOnResolverFailure: record.dnssec.defaultOnResolverFailure,
        resolver: {
          primary: {
            address: IpAddress.create(record.dnssec.resolver.primary.address),
            port: Port.create(record.dnssec.resolver.primary.port),
          },
          secondary: {
            address: record.dnssec.resolver.secondary.address
              ? IpAddress.create(record.dnssec.resolver.secondary.address)
              : null,
            port: Port.create(record.dnssec.resolver.secondary.port),
          },
          transport: record.dnssec.resolver.transport,
          timeoutMs: record.dnssec.resolver.timeoutMs,
          retries: record.dnssec.resolver.retries,
        },
        cache: {
          enabled: record.dnssec.cache.enabled,
          maxEntries: record.dnssec.cache.maxEntries,
          ttlSeconds: record.dnssec.cache.ttlSeconds,
        },
      },
    );
  }

  static toRecord(config: DnsInspectionConfig): DnsInspectionRecord {
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
