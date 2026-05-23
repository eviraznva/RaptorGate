import { Injectable, Logger } from '@nestjs/common';
import type {
  ILdapAuthenticator,
  LdapAuthRequest,
  LdapAuthResult,
} from '../../../application/ports/ldap-authenticator.interface.js';
import { LDAP_RESULT_INVALID_CREDENTIALS } from './ldap-message.js';
import { TcpLdapClient } from './tcp-ldap-client.js';

@Injectable()
export class TcpLdapAuthenticatorAdapter implements ILdapAuthenticator {
  private readonly logger = new Logger(TcpLdapAuthenticatorAdapter.name);

  async authenticate(request: LdapAuthRequest): Promise<LdapAuthResult> {
    const directory = request.options;

    if (!directory.enabled) {
      return { kind: 'disabled' };
    }
    if (!isSafeFilterValue(request.username)) {
      return {
        kind: 'error',
        message: 'username contains characters not allowed in LDAP filter',
      };
    }

    const client = new TcpLdapClient({
      host: directory.host,
      port: directory.port,
      timeoutMs: directory.connectTimeoutMs,
      tlsMode: directory.tlsMode,
      verifyServerCertificate: directory.verifyServerCertificate,
      servername: directory.servername,
    });
    try {
      await client.connect();

      const serviceBind = await client.bind(
        directory.bindDn,
        directory.bindPassword,
      );
      if (!TcpLdapClient.isResultSuccess(serviceBind)) {
        return {
          kind: 'error',
          message: `LDAP service bind failed (code=${serviceBind.resultCode}, ${serviceBind.diagnosticMessage || 'no message'})`,
        };
      }

      const userSearch = await client.searchEqualityMatch({
        baseDn: directory.userBaseDn,
        filterAttribute: directory.userFilterAttribute,
        filterValue: request.username,
        attributes: ['1.1'],
        sizeLimit: 1,
        timeLimitSeconds: Math.max(1, Math.floor(directory.searchTimeoutMs / 1000)),
      });
      if (TcpLdapClient.isNoSuchObject(userSearch.result)) {
        return { kind: 'reject', reason: 'LDAP user was not found' };
      }
      if (!TcpLdapClient.isResultSuccess(userSearch.result)) {
        return {
          kind: 'error',
          message: `LDAP user search failed (code=${userSearch.result.resultCode})`,
        };
      }
      if (userSearch.entries.length === 0) {
        return { kind: 'reject', reason: 'LDAP user was not found' };
      }

      const userDn = userSearch.entries[0].dn;
      const groupSearch = await client.searchEqualityMatch({
        baseDn: directory.groupBaseDn,
        filterAttribute: directory.groupMemberAttribute,
        filterValue: request.username,
        attributes: [directory.groupNameAttribute],
        sizeLimit: 0,
        timeLimitSeconds: Math.max(1, Math.floor(directory.searchTimeoutMs / 1000)),
      });
      if (!TcpLdapClient.isNoSuchObject(groupSearch.result)) {
        if (!TcpLdapClient.isResultSuccess(groupSearch.result)) {
          return {
            kind: 'error',
            message: `LDAP group search failed (code=${groupSearch.result.resultCode})`,
          };
        }
      }

      const userBind = await client.bind(userDn, request.password);
      if (TcpLdapClient.isResultSuccess(userBind)) {
        const groups = TcpLdapClient.isNoSuchObject(groupSearch.result)
          ? []
          : collectGroups(groupSearch.entries, directory.groupNameAttribute);

        this.logger.log({
          event: 'auth.ldap.bind_accept',
          message: 'LDAP user bind accepted',
          username: request.username,
          userDn,
          groupCount: groups.length,
        });
        return { kind: 'accept', userDn, groups };
      }
      if (userBind.resultCode === LDAP_RESULT_INVALID_CREDENTIALS) {
        return { kind: 'reject', reason: 'LDAP invalid credentials' };
      }

      return {
        kind: 'error',
        message: `LDAP user bind failed (code=${userBind.resultCode}, ${userBind.diagnosticMessage || 'no message'})`,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      this.logger.error({
        event: 'auth.ldap.error',
        message: 'LDAP authentication failed',
        username: request.username,
        error: message,
      });
      return message.toLowerCase().includes('timeout')
        ? { kind: 'timeout', message }
        : { kind: 'error', message };
    } finally {
      await client.unbindAndClose();
    }
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
      return false;
    }
  }
  return true;
}
