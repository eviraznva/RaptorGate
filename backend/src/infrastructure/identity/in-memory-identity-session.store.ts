import { Injectable } from '@nestjs/common';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import type { IIdentitySessionStore } from '../../domain/repositories/identity-session-store.js';

// In-memory store sesji identity. Per ADR 0002 sesje sa runtime state,
// nie persystujemy ich na dysk; restart backendu czysci store.
@Injectable()
export class InMemoryIdentitySessionStore implements IIdentitySessionStore {
  private readonly byIp = new Map<string, IdentitySession>();
  private readonly locks = new Map<string, Promise<void>>();

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
    this.byIp.set(session.getSourceIp().getValue, session);
  }

  async findBySourceIp(sourceIp: string): Promise<IdentitySession | null> {
    return this.byIp.get(sourceIp) ?? null;
  }

  async removeBySourceIp(sourceIp: string): Promise<IdentitySession | null> {
    const existing = this.byIp.get(sourceIp);
    if (!existing) return null;

    this.byIp.delete(sourceIp);
    return existing;
  }

  async peekExpired(now: Date): Promise<IdentitySession[]> {
    const expired: IdentitySession[] = [];

    for (const session of this.byIp.values()) {
      if (session.isExpiredAt(now)) {
        expired.push(session);
      }
    }

    return expired;
  }

  async listAll(): Promise<IdentitySession[]> {
    return Array.from(this.byIp.values());
  }
}
