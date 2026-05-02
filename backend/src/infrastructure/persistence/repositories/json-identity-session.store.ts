import { Inject, Injectable } from '@nestjs/common';
import { join } from 'node:path';
import { IdentitySession } from '../../../domain/entities/identity-session.entity.js';
import type { IIdentitySessionStore } from '../../../domain/repositories/identity-session-store.js';
import { IdentitySessionJsonMapper } from '../mappers/identity-session-json.mapper.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import {
  IdentitySessionsFileSchema,
  type IdentitySessionsFile,
} from '../schemas/identity-sessions.schema.js';

@Injectable()
export class JsonIdentitySessionStore implements IIdentitySessionStore {
  private readonly filePath = join(process.cwd(), 'data/json-db/identity_sessions.json');
  private readonly byIp = new Map<string, IdentitySession>();
  private readonly locks = new Map<string, Promise<void>>();
  private loaded = false;

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  async runExclusiveBySourceIp<T>(sourceIp: string, action: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(sourceIp) ?? Promise.resolve();
    let release: () => void = () => undefined;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.catch(() => undefined).then(() => current);
    this.locks.set(sourceIp, tail);

    await previous.catch(() => undefined);
    try {
      return await action();
    } finally {
      release();
      if (this.locks.get(sourceIp) === tail) {
        this.locks.delete(sourceIp);
      }
    }
  }

  async upsert(session: IdentitySession): Promise<void> {
    await this.mutex.runExclusive(async () => {
      await this.loadIfNeeded();
      const key = session.getSourceIp().getValue;
      const next = new Map(this.byIp);
      next.set(key, session);
      await this.persist(next);
      this.byIp.clear();
      for (const [ip, value] of next) {
        this.byIp.set(ip, value);
      }
    });
  }

  async findBySourceIp(sourceIp: string): Promise<IdentitySession | null> {
    return this.mutex.runExclusive(async () => {
      await this.loadIfNeeded();
      return this.byIp.get(sourceIp) ?? null;
    });
  }

  async removeBySourceIp(sourceIp: string): Promise<IdentitySession | null> {
    return this.mutex.runExclusive(async () => {
      await this.loadIfNeeded();
      const existing = this.byIp.get(sourceIp) ?? null;
      if (!existing) return null;

      const next = new Map(this.byIp);
      next.delete(sourceIp);
      await this.persist(next);
      this.byIp.clear();
      for (const [ip, value] of next) {
        this.byIp.set(ip, value);
      }
      return existing;
    });
  }

  async peekExpired(now: Date): Promise<IdentitySession[]> {
    return this.mutex.runExclusive(async () => {
      await this.loadIfNeeded();
      const expired: IdentitySession[] = [];

      for (const session of this.byIp.values()) {
        if (session.isExpiredAt(now)) {
          expired.push(session);
        }
      }

      return expired;
    });
  }

  async listAll(): Promise<IdentitySession[]> {
    return this.mutex.runExclusive(async () => {
      await this.loadIfNeeded();
      return Array.from(this.byIp.values());
    });
  }

  private async loadIfNeeded(): Promise<void> {
    if (this.loaded) return;

    const payload = await this.readPayload();
    this.byIp.clear();
    for (const record of payload.items) {
      const session = IdentitySessionJsonMapper.toDomain(record);
      this.byIp.set(session.getSourceIp().getValue, session);
    }
    this.loaded = true;
  }

  private async persist(sessions: Map<string, IdentitySession>): Promise<void> {
    const payload: IdentitySessionsFile = {
      items: Array.from(sessions.values()).map((session) =>
        IdentitySessionJsonMapper.toRecord(session),
      ),
    };
    await this.fileStore.writeJsonAtomic(this.filePath, payload);
  }

  private async readPayload(): Promise<IdentitySessionsFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return IdentitySessionsFileSchema.parse(raw);
  }
}
