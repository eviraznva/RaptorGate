import { Inject, Injectable } from '@nestjs/common';
import { join } from 'node:path';
import { SecretRecord } from '../../../domain/entities/secret-record.entity.js';
import type { ISecretStoreRepository } from '../../../domain/repositories/secret-store.repository.js';
import { SecretRecordJsonMapper } from '../mappers/secret-record-json.mapper.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import {
  SecretsFileSchema,
  type SecretsFile,
} from '../schemas/secrets.schema.js';

@Injectable()
export class JsonSecretStoreRepository implements ISecretStoreRepository {
  private readonly filePath = join(process.cwd(), 'data/json-db/secrets.json');

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  async exists(ref: string): Promise<boolean> {
    return (await this.findByRef(ref)) !== null;
  }

  async findByRef(ref: string): Promise<SecretRecord | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((item) => item.ref === ref);
    return row ? SecretRecordJsonMapper.toDomain(row) : null;
  }

  async save(record: SecretRecord): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      const next = SecretRecordJsonMapper.toRecord(record);
      const idx = payload.items.findIndex((item) => item.ref === next.ref);

      if (idx >= 0) {
        payload.items[idx] = next;
      } else {
        payload.items.push(next);
      }

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async delete(ref: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      payload.items = payload.items.filter((item) => item.ref !== ref);
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  private async readPayload(): Promise<SecretsFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return SecretsFileSchema.parse(raw);
  }
}
