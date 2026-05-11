import { Inject, Injectable } from '@nestjs/common';
import { join } from 'node:path';
import type { ISslBypassRepository } from '../../../domain/repositories/ssl-bypass.repository.js';
import { SslBypassEntry } from '../../../domain/entities/ssl-bypass-entry.entity.js';
import {
  SslBypassListFileSchema,
  type SslBypassListFile,
} from '../schemas/ssl-bypass-list.schema.js';
import { SslBypassJsonMapper } from '../mappers/ssl-bypass-json.mapper.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';

@Injectable()
export class JsonSslBypassRepository implements ISslBypassRepository {
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/ssl_bypass_list.json',
  );

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<SslBypassListFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });
    return SslBypassListFileSchema.parse(raw);
  }

  async save(entry: SslBypassEntry, createdBy?: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      const idx = payload.items.findIndex((i) => i.id === entry.getId());
      const nextCreatedBy =
        idx >= 0 ? payload.items[idx].createdBy : createdBy;

      if (!nextCreatedBy) {
        throw new Error('createdBy is required when creating a bypass entry');
      }

      const next = SslBypassJsonMapper.toRecord(entry, nextCreatedBy);

      if (idx >= 0) {
        payload.items[idx] = next;
      } else {
        payload.items.push(next);
      }

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async overwriteAll(entries: SslBypassEntry[]): Promise<void> {
    const items = entries.map((e) =>
      SslBypassJsonMapper.toRecord(e, crypto.randomUUID()),
    );

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, { items });
    });
  }

  async findById(id: string): Promise<SslBypassEntry | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((i) => i.id === id);
    return row ? SslBypassJsonMapper.toDomain(row) : null;
  }

  async findAll(): Promise<SslBypassEntry[]> {
    const payload = await this.readPayload();
    return payload.items.map((i) => SslBypassJsonMapper.toDomain(i));
  }

  async findActive(): Promise<SslBypassEntry[]> {
    const payload = await this.readPayload();
    return payload.items
      .filter((i) => i.isActive)
      .map((i) => SslBypassJsonMapper.toDomain(i));
  }

  async delete(id: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      payload.items = payload.items.filter((i) => i.id !== id);
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
