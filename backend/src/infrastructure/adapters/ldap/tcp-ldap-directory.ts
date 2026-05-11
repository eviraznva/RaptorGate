import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  ILdapDirectory,
  LdapDirectoryOptions,
  LdapGroupLookupResult,
} from '../../../application/ports/ldap-directory.interface.js';
import type { Env } from '../../../shared/config/env.validation.js';
import { TcpLdapClient } from './tcp-ldap-client.js';

// Adapter LDAPv3: bind admin -> search uzytkownika -> search grup po memberUid.
// Zakres jest ograniczony do tego co labowy slapd faktycznie obsluguje (ADR 0005).
@Injectable()
export class TcpLdapDirectoryAdapter implements ILdapDirectory {
  private readonly logger = new Logger(TcpLdapDirectoryAdapter.name);

  constructor(
    @Inject(ConfigService)
    private readonly config: ConfigService<Env, true>,
  ) {}

  isEnabled(): boolean {
    return this.config.get('IDENTITY_LDAP_ENABLED', { infer: true });
  }

  async resolveGroups(
    username: string,
    options?: LdapDirectoryOptions,
  ): Promise<LdapGroupLookupResult> {
    const directory = options ?? this.optionsFromEnv();

    if (!directory.enabled) {
      return { kind: 'disabled' };
    }
    if (directory.tlsMode !== 'disabled') {
      return {
        kind: 'error',
        message: `LDAP tlsMode ${directory.tlsMode} is not supported by the TCP adapter`,
      };
    }
    if (!isSafeFilterValue(username)) {
      return {
        kind: 'error',
        message: 'username contains characters not allowed in LDAP filter',
      };
    }

    const client = new TcpLdapClient({
      host: directory.host,
      port: directory.port,
      timeoutMs: directory.timeoutMs,
    });
    try {
      await client.connect();

      const bindResult = await client.bind(
        directory.bindDn,
        directory.bindPassword,
      );
      if (!TcpLdapClient.isResultSuccess(bindResult)) {
        return {
          kind: 'error',
          message: `LDAP bind failed (code=${bindResult.resultCode}, ${bindResult.diagnosticMessage || 'no message'})`,
        };
      }

      const userSearch = await client.searchEqualityMatch({
        baseDn: directory.userBaseDn,
        filterAttribute: directory.userFilterAttribute,
        filterValue: username,
        attributes: ['1.1'],
        sizeLimit: 1,
        timeLimitSeconds: Math.max(1, Math.floor(directory.timeoutMs / 1000)),
      });
      if (TcpLdapClient.isNoSuchObject(userSearch.result)) {
        return { kind: 'not-found' };
      }
      if (!TcpLdapClient.isResultSuccess(userSearch.result)) {
        return {
          kind: 'error',
          message: `LDAP user search failed (code=${userSearch.result.resultCode})`,
        };
      }
      if (userSearch.entries.length === 0) {
        return { kind: 'not-found' };
      }
      const userDn = userSearch.entries[0].dn;

      const groupSearch = await client.searchEqualityMatch({
        baseDn: directory.groupBaseDn,
        filterAttribute: directory.groupMemberAttribute,
        filterValue: username,
        attributes: [directory.groupNameAttribute],
        sizeLimit: 0,
        timeLimitSeconds: Math.max(1, Math.floor(directory.timeoutMs / 1000)),
      });
      if (TcpLdapClient.isNoSuchObject(groupSearch.result)) {
        return { kind: 'ok', userDn, groups: [] };
      }
      if (!TcpLdapClient.isResultSuccess(groupSearch.result)) {
        return {
          kind: 'error',
          message: `LDAP group search failed (code=${groupSearch.result.resultCode})`,
        };
      }

      const groups = collectGroups(
        groupSearch.entries,
        directory.groupNameAttribute,
      );

      this.logger.log({
        event: 'identity.ldap.lookup',
        message: 'LDAP groups resolved',
        username,
        userDn,
        groupCount: groups.length,
      });
      return { kind: 'ok', userDn, groups };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      this.logger.error({
        event: 'identity.ldap.error',
        message: 'LDAP lookup failed',
        username,
        error: message,
      });
      return { kind: 'error', message };
    } finally {
      await client.unbindAndClose();
    }
  }

  // TODO(Issue G): remove env fallback after sessions carry auth profile context.
  private optionsFromEnv(): LdapDirectoryOptions {
    return {
      enabled: this.config.get('IDENTITY_LDAP_ENABLED', { infer: true }),
      host: this.config.get('IDENTITY_LDAP_HOST', { infer: true }),
      port: this.config.get('IDENTITY_LDAP_PORT', { infer: true }),
      tlsMode: 'disabled',
      bindDn: this.config.get('IDENTITY_LDAP_BIND_DN', { infer: true }),
      bindPassword: this.config.get('IDENTITY_LDAP_BIND_PASSWORD', {
        infer: true,
      }),
      userBaseDn: this.config.get('IDENTITY_LDAP_USER_BASE_DN', {
        infer: true,
      }),
      userFilterAttribute: this.config.get(
        'IDENTITY_LDAP_USER_FILTER_ATTRIBUTE',
        { infer: true },
      ),
      groupBaseDn: this.config.get('IDENTITY_LDAP_GROUP_BASE_DN', {
        infer: true,
      }),
      groupMemberAttribute: this.config.get(
        'IDENTITY_LDAP_GROUP_MEMBER_ATTRIBUTE',
        { infer: true },
      ),
      groupNameAttribute: this.config.get('IDENTITY_LDAP_GROUP_NAME_ATTRIBUTE', {
        infer: true,
      }),
      timeoutMs: this.config.get('IDENTITY_LDAP_TIMEOUT_MS', { infer: true }),
    };
  }
}

function collectGroups(
  entries: { dn: string; attributes: Map<string, string[]> }[],
  attributeName: string,
): string[] {
  const out: string[] = [];
  for (const entry of entries) {
    const values = entry.attributes.get(attributeName) ?? [];
    for (const raw of values) {
      const trimmed = raw.trim();
      if (trimmed && !out.includes(trimmed)) out.push(trimmed);
    }
  }
  return out;
}

function isSafeFilterValue(value: string): boolean {
  if (value.length === 0 || value.length > 256) return false;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0) return false;
    if (code === 0x28 || code === 0x29 || code === 0x2a || code === 0x5c) {
      // ( ) * \ — RFC 4515 specials, blokujemy zamiast escapowac, bo username
      // z labu nie zawiera tych znakow i bezpieczniej jest fail-fast.
      return false;
    }
  }
  return true;
}
