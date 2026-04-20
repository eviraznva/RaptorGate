import { join } from "node:path";
import { Inject, Injectable } from "@nestjs/common";
import { IpsConfig } from "src/domain/entities/ips-config.entity";
import { IIpsConfigRepository } from "src/domain/repositories/ips-config.repository";
import { Mutex } from "../json/file-mutex";
import { FileStore } from "../json/file-store";
import { IpsConfigJsonMapper } from "../mappers/ips-config-json.mapper";
import {
  defaultIpsConfig,
  IpsConfigRecord,
  IpsConfigSchema,
} from "../schemas/ips-config.schema";

@Injectable()
export class JsonIpsConfigRepository implements IIpsConfigRepository {
  private readonly filePath = join(
    process.cwd(),
    "data/json-db/ips_configuration.json",
  );

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<IpsConfigRecord> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(
      this.filePath,
      defaultIpsConfig,
    );

    return IpsConfigSchema.parse(raw);
  }

  async get(): Promise<IpsConfig> {
    const payload = await this.readPayload();

    return IpsConfigJsonMapper.toDomain(payload);
  }

  async save(ispConfig: IpsConfig): Promise<void> {
    const payload = IpsConfigJsonMapper.toRecord(ispConfig);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
