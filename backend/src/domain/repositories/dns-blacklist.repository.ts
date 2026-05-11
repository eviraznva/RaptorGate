import { DnsBlacklistEntry } from "../entities/dns-blacklist-entry.entity";

export interface IDnsBlacklistRepository {
  save(dnsBacklistEntry: DnsBlacklistEntry): Promise<void>;
  findById(id: string): Promise<DnsBlacklistEntry | null>;
  findAll(): Promise<DnsBlacklistEntry[]>;
  findActive(): Promise<DnsBlacklistEntry[]>;
  delete(id: string): Promise<void>;
}

export const DNS_BLACLIST_REPOSITORY_TOKEN = Symbol(
  "DNS_BLACLIST_REPOSITORY_TOKEN",
);
