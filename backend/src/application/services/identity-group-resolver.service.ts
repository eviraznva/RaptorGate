import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  LDAP_DIRECTORY_TOKEN,
  type ILdapDirectory,
} from '../ports/ldap-directory.interface.js';
import {
  LDAP_GROUP_CACHE_TOKEN,
  type ILdapGroupCache,
} from '../ports/ldap-group-cache.interface.js';
import type { Env } from '../../shared/config/env.validation.js';

// Pojedyncze zrodlo prawdy dla "user -> groups" dla polityk identity (Issue 4).
// Priorytet: LDAP gdy enabled i jako primary. VSA jest shortcutem MVP — uzywany
// gdy LDAP jest disabled, ustawiony jako primary=vsa, lub zwroci blad.
//
// Decyzje rozdzielenia LDAP/VSA opisuje ADR 0005.

export type IdentityGroupSource = 'ldap' | 'ldap-cache' | 'vsa' | 'none';

export type IdentityGroupLdapDiagnostic =
  | 'ok'
  | 'cache-hit'
  | 'not-found'
  | 'error'
  | 'disabled'
  | 'skipped';

export interface IdentityGroupResolution {
  groups: string[];
  source: IdentityGroupSource;
  // externalId — DN z LDAP gdy source=ldap; inaczej username (VSA/none/cache).
  // Cache nie pamieta DN celowo, zeby nie sztywno wiazac wpisu z konkretnym DN
  // przy zmianie OU; refresher trafi na cache miss i zaktualizuje.
  externalId: string;
  ldapDiagnostic: IdentityGroupLdapDiagnostic;
  ldapError?: string;
}

export interface ResolveGroupsInput {
  username: string;
  vsaGroups: string[];
}

@Injectable()
export class IdentityGroupResolverService {
  private readonly logger = new Logger(IdentityGroupResolverService.name);

  constructor(
    @Inject(LDAP_DIRECTORY_TOKEN)
    private readonly directory: ILdapDirectory,
    @Inject(LDAP_GROUP_CACHE_TOKEN)
    private readonly cache: ILdapGroupCache,
    @Inject(ConfigService)
    private readonly config: ConfigService<Env, true>,
  ) {}

  async resolve(input: ResolveGroupsInput): Promise<IdentityGroupResolution> {
    const primary = this.config.get('IDENTITY_GROUP_SOURCE_PRIMARY', {
      infer: true,
    });
    const ldapEnabled = this.directory.isEnabled();

    if (!ldapEnabled) {
      return this.fallbackToVsa(input, 'disabled');
    }
    if (primary !== 'ldap') {
      return this.fallbackToVsa(input, 'skipped');
    }

    const cached = this.cache.get(input.username);
    if (cached) {
      return {
        groups: cached,
        source: 'ldap-cache',
        externalId: input.username,
        ldapDiagnostic: 'cache-hit',
      };
    }

    const lookup = await this.directory.resolveGroups(input.username);
    if (lookup.kind === 'ok') {
      this.cache.set(input.username, lookup.groups);
      return {
        groups: lookup.groups,
        source: 'ldap',
        externalId: lookup.userDn,
        ldapDiagnostic: 'ok',
      };
    }
    if (lookup.kind === 'not-found') {
      this.logger.warn({
        event: 'identity.ldap.user_not_found',
        message: 'LDAP did not find user, falling back to VSA',
        username: input.username,
      });
      return this.fallbackToVsa(input, 'not-found');
    }
    if (lookup.kind === 'disabled') {
      // Nie powinno sie wydarzyc: isEnabled() bylo true, ale na wszelki wypadek.
      return this.fallbackToVsa(input, 'disabled');
    }

    this.logger.error({
      event: 'identity.ldap.error',
      message: 'LDAP lookup failed, falling back to VSA',
      username: input.username,
      error: lookup.message,
    });
    return {
      ...this.fallbackToVsa(input, 'error'),
      ldapError: lookup.message,
    };
  }

  invalidate(username: string): void {
    this.cache.invalidate(username);
  }

  private fallbackToVsa(
    input: ResolveGroupsInput,
    diagnostic: IdentityGroupLdapDiagnostic,
  ): IdentityGroupResolution {
    if (input.vsaGroups.length === 0) {
      return {
        groups: [],
        source: 'none',
        externalId: input.username,
        ldapDiagnostic: diagnostic,
      };
    }
    return {
      groups: dedup(input.vsaGroups),
      source: 'vsa',
      externalId: input.username,
      ldapDiagnostic: diagnostic,
    };
  }
}

function dedup(values: string[]): string[] {
  const out: string[] = [];
  for (const raw of values) {
    const trimmed = raw.trim();
    if (trimmed && !out.includes(trimmed)) out.push(trimmed);
  }
  return out;
}
