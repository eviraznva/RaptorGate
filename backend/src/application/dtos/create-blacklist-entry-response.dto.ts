import { DnsBlacklistEntry } from "src/domain/entities/dns-blacklist-entry.entity";

export class CreateDnsBlacklistEntryResponseDto {
  entry: DnsBlacklistEntry[];
}
