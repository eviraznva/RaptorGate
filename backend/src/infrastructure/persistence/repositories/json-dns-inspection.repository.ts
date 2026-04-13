import { join } from "node:path";
import { Inject, Injectable } from "@nestjs/common";
import { DnsInspectionConfig } from "../../../domain/entities/dns-inspection-config.entity.js";
import { IDnsInspectionRepository } from "../../../domain/repositories/dns-inspection.repository.js";
import { FileStore } from "../json/file-store.js";
import { Mutex } from "../json/file-mutex.js";
import { DnsInspectionJsonMapper } from "../mappers/dns-inspection-json.mapper.js";
import {
  defaultDnsInspectionRecord,
  DnsInspectionRecord,
  DnsInspectionRecordSchema,
} from "../schemas/dns-inspection.schema.js";

@Injectable()
export class JsonDnsInspectionRepository implements IDnsInspectionRepository {
  private readonly filePath = join(
    process.cwd(),
    "data/json-db/dns_inspection.json",
  );

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<DnsInspectionRecord> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(
      this.filePath,
      defaultDnsInspectionRecord,
    );

    return DnsInspectionRecordSchema.parse(raw);
  }

  async get(): Promise<DnsInspectionConfig> {
    const payload = await this.readPayload();
    return DnsInspectionJsonMapper.toDomain(payload);
  }

  async save(config: DnsInspectionConfig): Promise<void> {
    const payload = DnsInspectionJsonMapper.toRecord(config);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
