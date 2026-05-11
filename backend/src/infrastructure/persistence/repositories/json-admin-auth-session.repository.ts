import { Inject, Injectable } from '@nestjs/common';
import { join } from 'node:path';
import type { AdminAuthSession } from '../../../domain/entities/admin-auth-session.entity.js';
import type { IAdminAuthSessionRepository } from '../../../domain/repositories/admin-auth-session.repository.js';
import { AdminAuthSessionJsonMapper } from '../mappers/admin-auth-session-json.mapper.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import {
  AdminAuthSessionsFileSchema,
  type AdminAuthSessionRecord,
  type AdminAuthSessionsFile,
} from '../schemas/admin-auth-sessions.schema.js';

@Injectable()
export class JsonAdminAuthSessionRepository implements IAdminAuthSessionRepository {
  private readonly filePath = join(process.cwd(), 'data/json-db/admin_auth_sessions.json');

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  async findById(id: string): Promise<AdminAuthSession | null> {
    return this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      const purged = this.purgeExpiredOrRevoked(payload, new Date());
      if (purged.changed) {
        await this.fileStore.writeJsonAtomic(this.filePath, purged.payload);
      }
      const row = purged.payload.items.find((item) => item.id === id);
      return row ? AdminAuthSessionJsonMapper.toDomain(row) : null;
    });
  }

  async save(session: AdminAuthSession): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = this.purgeExpiredOrRevoked(
        await this.readPayload(),
        new Date(),
      ).payload;
      const next = AdminAuthSessionJsonMapper.toRecord(session);
      const idx = payload.items.findIndex((item) => item.id === next.id);

      if (idx >= 0) {
        payload.items[idx] = next;
      } else {
        payload.items.push(next);
      }

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async revoke(id: string, revokedAt: Date): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      const row = payload.items.find((item) => item.id === id);
      if (!row) return;
      row.revokedAt = revokedAt.toISOString();
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  private async readPayload(): Promise<AdminAuthSessionsFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return AdminAuthSessionsFileSchema.parse(raw);
  }

  private purgeExpiredOrRevoked(
    payload: AdminAuthSessionsFile,
    now: Date,
  ): { payload: AdminAuthSessionsFile; changed: boolean } {
    const items = payload.items.filter((item) => !isExpiredOrRevoked(item, now));
    return {
      payload: { items },
      changed: items.length !== payload.items.length,
    };
  }
}

function isExpiredOrRevoked(record: AdminAuthSessionRecord, now: Date): boolean {
  return record.revokedAt !== null || new Date(record.refreshTokenExpiry).getTime() <= now.getTime();
}
