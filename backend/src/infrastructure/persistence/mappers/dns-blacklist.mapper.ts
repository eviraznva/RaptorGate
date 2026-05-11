import { DnsBlacklistEntry } from "src/domain/entities/dns-blacklist-entry.entity";
import { DomainName } from "src/domain/value-objects/domain-name.vo";
import { DnsBlacklistRecord } from "../schemas/dns-blacklist.schema";

export class DnsBlacklistJsonMapper {
  constructor() {}

  static toDomain(record: DnsBlacklistRecord): DnsBlacklistEntry {
    return DnsBlacklistEntry.create(
      record.id,
      DomainName.create(record.domain),
      record.reason,
      record.isActive,
      new Date(record.createdAt),
      record.createdBy,
    );
  }

  static toRecord(dnsBlacklist: DnsBlacklistEntry): DnsBlacklistRecord {
    return {
      id: dnsBlacklist.getId(),
      domain: dnsBlacklist.getDomain(),
      reason: dnsBlacklist.getReason(),
      isActive: dnsBlacklist.getIsActive(),
      createdAt: dnsBlacklist.getCreatedAt().toISOString(),
      createdBy: dnsBlacklist.getCreatedBy(),
    };
  }
}
