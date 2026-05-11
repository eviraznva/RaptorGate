import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { ILdapGroupCache } from '../../application/ports/ldap-group-cache.interface.js';
import type { Env } from '../../shared/config/env.validation.js';

interface Entry {
  groups: string[];
  expiresAtMs: number;
}

// Wpisy starzeja sie po IDENTITY_LDAP_GROUP_CACHE_TTL_SECONDS — refresher
// (Issue 4) trafi w miss i pociagnie swieze grupy z LDAP. Cache nie wie nic
// o sesjach identity, zeby grupy mogly istniec niezaleznie od logowania.
@Injectable()
export class InMemoryLdapGroupCache implements ILdapGroupCache {
  private readonly entries = new Map<string, Entry>();
  private readonly ttlMs: number;

  constructor(
    @Inject(ConfigService)
    config: ConfigService<Env, true>,
  ) {
    const ttlSeconds = config.get('IDENTITY_LDAP_GROUP_CACHE_TTL_SECONDS', {
      infer: true,
    });
    this.ttlMs = ttlSeconds * 1000;
  }

  get(username: string): string[] | null {
    const entry = this.entries.get(username);
    if (!entry) return null;
    if (entry.expiresAtMs <= Date.now()) {
      this.entries.delete(username);
      return null;
    }
    return [...entry.groups];
  }

  set(username: string, groups: string[]): void {
    this.entries.set(username, {
      groups: [...groups],
      expiresAtMs: Date.now() + this.ttlMs,
    });
  }

  invalidate(username: string): void {
    this.entries.delete(username);
  }
}
