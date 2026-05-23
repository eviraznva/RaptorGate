import { beforeEach, describe, expect, it, jest } from 'bun:test';
import { ConfigService } from '@nestjs/config';
import type {
  ILdapDirectory,
  LdapGroupLookupResult,
} from '../ports/ldap-directory.interface.js';
import type { ILdapGroupCache } from '../ports/ldap-group-cache.interface.js';
import { IdentityGroupResolverService } from './identity-group-resolver.service.js';

function makeConfig(primary: 'ldap' | 'vsa' = 'ldap'): ConfigService {
  return {
    get: () => primary,
  } as unknown as ConfigService;
}

describe('IdentityGroupResolverService', () => {
  let directory: jest.Mocked<ILdapDirectory>;
  let cache: jest.Mocked<ILdapGroupCache>;
  let service: IdentityGroupResolverService;

  beforeEach(() => {
    directory = {
      isEnabled: jest.fn(() => true),
      resolveGroups: jest.fn<() => Promise<LdapGroupLookupResult>>(),
    };
    cache = {
      get: jest.fn(() => null),
      set: jest.fn(),
      invalidate: jest.fn(),
    } as unknown as jest.Mocked<ILdapGroupCache>;
  });

  function build(primary: 'ldap' | 'vsa' = 'ldap'): void {
    service = new IdentityGroupResolverService(
      directory,
      cache,
      makeConfig(primary) as unknown as ConstructorParameters<
        typeof IdentityGroupResolverService
      >[2],
    );
  }

  it('uzywa LDAP gdy enabled i primary=ldap, zapisuje cache', async () => {
    build('ldap');
    directory.resolveGroups.mockResolvedValue({
      kind: 'ok',
      userDn: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      groups: ['admins'],
    });

    const result = await service.resolve({
      username: 'admin',
      vsaGroups: ['ignored'],
    });

    expect(result.source).toBe('ldap');
    expect(result.groups).toEqual(['admins']);
    expect(result.externalId).toBe('uid=admin,ou=users,dc=raptorgate,dc=local');
    expect(cache.set).toHaveBeenCalledWith('admin', ['admins']);
  });

  it('zwraca z cache bez wolania LDAP', async () => {
    build('ldap');
    cache.get.mockReturnValueOnce(['admins']);

    const result = await service.resolve({ username: 'admin', vsaGroups: [] });

    expect(result.source).toBe('ldap-cache');
    expect(result.ldapDiagnostic).toBe('cache-hit');
    expect(directory.resolveGroups).not.toHaveBeenCalled();
  });

  it('pomija cache przy forceRefresh i zapisuje nowy wynik LDAP', async () => {
    build('ldap');
    cache.get.mockReturnValueOnce(['admins']);
    directory.resolveGroups.mockResolvedValue({
      kind: 'ok',
      userDn: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      groups: ['admins', 'auditors'],
    });

    const result = await service.resolve({
      username: 'admin',
      vsaGroups: [],
      forceRefresh: true,
    });

    expect(result.source).toBe('ldap');
    expect(result.groups).toEqual(['admins', 'auditors']);
    expect(cache.get).not.toHaveBeenCalled();
    expect(cache.set).toHaveBeenCalledWith('admin', ['admins', 'auditors']);
  });

  it('passes selected ldap profile options to directory lookup', async () => {
    build('ldap');
    directory.resolveGroups.mockResolvedValue({
      kind: 'ok',
      userDn: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      groups: ['admins'],
    });
    const ldapOptions = {
      enabled: true,
      host: 'ldap.example.test',
      port: 636,
      tlsMode: 'ldaps' as const,
      verifyServerCertificate: true,
      servername: 'ldap.example.test',
      bindDn: 'cn=admin,dc=raptorgate,dc=local',
      bindPassword: 'secret',
      userBaseDn: 'ou=users,dc=raptorgate,dc=local',
      userFilterAttribute: 'uid',
      userNameAttribute: 'uid',
      groupBaseDn: 'ou=groups,dc=raptorgate,dc=local',
      groupMemberAttribute: 'memberUid',
      groupNameAttribute: 'cn',
      includeGroups: [],
      connectTimeoutMs: 2000,
      searchTimeoutMs: 4000,
      timeoutMs: 4000,
    };

    await service.resolve({
      username: 'admin',
      vsaGroups: [],
      ldapOptions,
      forceRefresh: true,
    });

    expect(directory.resolveGroups).toHaveBeenCalledWith('admin', ldapOptions);
  });

  it('fallback na VSA gdy LDAP zwroci error i przekazuje ldapError diagnostycznie', async () => {
    build('ldap');
    directory.resolveGroups.mockResolvedValue({
      kind: 'error',
      message: 'ECONNREFUSED',
    });

    const result = await service.resolve({
      username: 'admin',
      vsaGroups: ['users'],
    });

    expect(result.source).toBe('vsa');
    expect(result.groups).toEqual(['users']);
    expect(result.ldapDiagnostic).toBe('error');
    expect(result.ldapError).toBe('ECONNREFUSED');
  });

  it('fallback na VSA gdy LDAP nie znajdzie usera', async () => {
    build('ldap');
    directory.resolveGroups.mockResolvedValue({ kind: 'not-found' });

    const result = await service.resolve({
      username: 'ghost',
      vsaGroups: ['guests'],
    });

    expect(result.source).toBe('vsa');
    expect(result.groups).toEqual(['guests']);
    expect(result.ldapDiagnostic).toBe('not-found');
  });

  it('VSA-only path gdy LDAP disabled', async () => {
    build('ldap');
    directory.isEnabled.mockReturnValue(false);

    const result = await service.resolve({
      username: 'user',
      vsaGroups: ['users'],
    });

    expect(result.source).toBe('vsa');
    expect(result.ldapDiagnostic).toBe('disabled');
    expect(directory.resolveGroups).not.toHaveBeenCalled();
  });

  it('VSA-only path gdy primary=vsa nawet przy LDAP enabled', async () => {
    build('vsa');

    const result = await service.resolve({
      username: 'user',
      vsaGroups: ['users'],
    });

    expect(result.source).toBe('vsa');
    expect(result.ldapDiagnostic).toBe('skipped');
    expect(directory.resolveGroups).not.toHaveBeenCalled();
  });

  it('source=none gdy ani LDAP ani VSA nie daja grup', async () => {
    build('vsa');

    const result = await service.resolve({ username: 'user', vsaGroups: [] });

    expect(result.source).toBe('none');
    expect(result.groups).toEqual([]);
    expect(result.externalId).toBe('user');
  });
});
