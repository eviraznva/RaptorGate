import { join } from "node:path";
import { Inject } from "@nestjs/common";
import { DnsBlacklistEntry } from "src/domain/entities/dns-blacklist-entry.entity";
import { IDnsBlacklistRepository } from "src/domain/repositories/dns-blacklist.repository";
import { Mutex } from "../json/file-mutex";
import { FileStore } from "../json/file-store";
import { DnsBlacklistJsonMapper } from "../mappers/dns-blacklist.mapper";
import {
  DnsBlacklistFile,
  DnsBlacklistFileSchema,
} from "../schemas/dns-blacklist.schema";

export class JsonDnsBlacklistRepository implements IDnsBlacklistRepository {
  private readonly filePath = join(
    process.cwd(),
    "data/json-db/dns_blacklist.json",
  );

  constructor(
    @Inject(Mutex) private readonly mutex: Mutex,
    @Inject(FileStore) private readonly fileStore: FileStore,
  ) {}

  private async readPayload(): Promise<DnsBlacklistFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return DnsBlacklistFileSchema.parse(raw);
  }

  async save(dnsBacklistEntry: DnsBlacklistEntry): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const dnsBlacklistEntries = await this.readPayload();
      const next = DnsBlacklistJsonMapper.toRecord(dnsBacklistEntry);

      const existingRow = await this.findById(dnsBacklistEntry.getId());
      if (existingRow) {
        dnsBlacklistEntries.items = dnsBlacklistEntries.items.map((d) =>
          d.id === dnsBacklistEntry.getId() ? next : d,
        );
      } else {
        dnsBlacklistEntries.items.push(next);
      }

      await this.fileStore.writeJsonAtomic(this.filePath, dnsBlacklistEntries);
    });
  }

  async findById(id: string): Promise<DnsBlacklistEntry | null> {
    const dnsBlacklistEntries = await this.readPayload();

    const dnsBlacklistEntryById = dnsBlacklistEntries.items.find(
      (d) => d.id === id,
    );
    if (!dnsBlacklistEntryById) return null;

    return DnsBlacklistJsonMapper.toDomain(dnsBlacklistEntryById);
  }

  async findAll(): Promise<DnsBlacklistEntry[]> {
    const dnsBlacklistEntries = await this.readPayload();
    if (!dnsBlacklistEntries.items.length) return [];

    return dnsBlacklistEntries.items.map((d) =>
      DnsBlacklistJsonMapper.toDomain(d),
    );
  }

  async findActive(): Promise<DnsBlacklistEntry[]> {
    const dnsBlacklistEntries = await this.readPayload();
    const activeDnsBlacklistEntries = dnsBlacklistEntries.items.filter(
      (d) => d.isActive,
    );

    return activeDnsBlacklistEntries.map((d) =>
      DnsBlacklistJsonMapper.toDomain(d),
    );
  }

  async delete(id: string): Promise<void> {
    const dnsBlacklistEntries = await this.readPayload();
    dnsBlacklistEntries.items = dnsBlacklistEntries.items.filter(
      (d) => d.id !== id,
    );

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, dnsBlacklistEntries);
    });
  }
}
