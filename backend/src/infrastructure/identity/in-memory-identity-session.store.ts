import { Injectable } from '@nestjs/common';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import type { IIdentitySessionStore } from '../../domain/repositories/identity-session-store.js';

// In-memory store sesji identity. Per ADR 0002 sesje sa runtime state,
// nie persystujemy ich na dysk — restart backendu czysci store.
@Injectable()
export class InMemoryIdentitySessionStore implements IIdentitySessionStore {
  private readonly byIp = new Map<string, IdentitySession>();

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

  async removeExpired(now: Date): Promise<IdentitySession[]> {
    const expired: IdentitySession[] = [];

    for (const [ip, session] of this.byIp) {
      if (session.isExpiredAt(now)) {
        expired.push(session);
        this.byIp.delete(ip);
      }
    }

    return expired;
  }

  async listAll(): Promise<IdentitySession[]> {
    return Array.from(this.byIp.values());
  }
}
