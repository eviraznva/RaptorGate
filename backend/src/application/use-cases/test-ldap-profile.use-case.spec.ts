import { describe, expect, it, jest } from 'bun:test';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import type { IIdentityConfigRepository } from '../../domain/repositories/identity-config.repository.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type {
  ILdapDirectory,
  LdapGroupLookupResult,
} from '../ports/ldap-directory.interface.js';
import type { ISecretResolverService } from '../ports/secret-resolver.service.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { TestLdapProfileUseCase } from './test-ldap-profile.use-case.js';

describe('TestLdapProfileUseCase', () => {
  it('tests the selected ldap profile with resolved bind password and profile settings', async () => {
    const now = new Date('2026-05-01T10:00:00.000Z');
    const ldap = LdapServerProfile.create(
      'ldap-1',
      'LDAP',
      null,
      true,
      '10.0.0.20',
      389,
      'disabled',
      'cn=admin,dc=example,dc=com',
      'secret://identity/ldap/default',
      'ou=users,dc=example,dc=com',
      'uid',
      'ou=groups,dc=example,dc=com',
      'memberUid',
      'cn',
      4000,
      300,
      now,
      now,
      'creator',
    );
    const repository = {
      find: jest.fn(async () =>
        IdentityConfiguration.create(
          [],
          [ldap],
          [],
          IdentitySettings.create(null, null, null, null),
        ),
      ),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const secretResolver = {
      resolve: jest.fn(async () => SecretValue.create('bind-password')),
    } as unknown as jest.Mocked<ISecretResolverService>;
    const ldapDirectory = {
      isEnabled: jest.fn(() => true),
      resolveGroups: jest.fn(async () => ({
        kind: 'ok',
        userDn: 'uid=admin,ou=users,dc=example,dc=com',
        groups: ['admins'],
      })),
    } as unknown as jest.Mocked<ILdapDirectory>;
    const useCase = new TestLdapProfileUseCase(
      repository,
      secretResolver,
      ldapDirectory,
      {
        decodeAccessToken: jest.fn(() => ({ sub: 'user-1', username: 'admin' })),
      } as unknown as ITokenService,
    );

    const result = await useCase.execute({
      accessToken: 'token',
      id: 'ldap-1',
      username: 'admin',
    });

    expect(result.result).toBe('ok');
    expect(result.groups).toEqual(['admins']);
    expect(ldapDirectory.resolveGroups).toHaveBeenCalledWith('admin', {
      enabled: true,
      host: '10.0.0.20',
      port: 389,
      tlsMode: 'disabled',
      verifyServerCertificate: false,
      servername: '10.0.0.20',
      bindDn: 'cn=admin,dc=example,dc=com',
      bindPassword: 'bind-password',
      userBaseDn: 'ou=users,dc=example,dc=com',
      userFilterAttribute: 'uid',
      userNameAttribute: 'uid',
      groupBaseDn: 'ou=groups,dc=example,dc=com',
      groupMemberAttribute: 'memberUid',
      groupNameAttribute: 'cn',
      includeGroups: [],
      connectTimeoutMs: 4000,
      searchTimeoutMs: 4000,
      timeoutMs: 4000,
    });
  });

  it('maps ldap not-found to diagnostic response', async () => {
    const { useCase } = makeUseCaseWithLdapResult({ kind: 'not-found' });

    const result = await useCase.execute({
      accessToken: 'token',
      id: 'ldap-1',
      username: 'missing',
    });

    expect(result.result).toBe('not_found');
    expect(result.message).toBe('LDAP user was not found');
  });

  it('maps ldap error to diagnostic response', async () => {
    const { useCase } = makeUseCaseWithLdapResult({
      kind: 'error',
      message: 'bind failed',
    });

    const result = await useCase.execute({
      accessToken: 'token',
      id: 'ldap-1',
      username: 'admin',
    });

    expect(result.result).toBe('error');
    expect(result.message).toBe('bind failed');
  });
});

function makeUseCaseWithLdapResult(result: LdapGroupLookupResult): {
  useCase: TestLdapProfileUseCase;
} {
  const now = new Date('2026-05-01T10:00:00.000Z');
  const ldap = LdapServerProfile.create(
    'ldap-1',
    'LDAP',
    null,
    true,
    '10.0.0.20',
    389,
    'disabled',
    'cn=admin,dc=example,dc=com',
    'secret://identity/ldap/default',
    'ou=users,dc=example,dc=com',
    'uid',
    'ou=groups,dc=example,dc=com',
    'memberUid',
    'cn',
    4000,
    300,
    now,
    now,
    'creator',
  );
  const repository = {
    find: jest.fn(async () =>
      IdentityConfiguration.create(
        [],
        [ldap],
        [],
        IdentitySettings.create(null, null, null, null),
      ),
    ),
  } as unknown as jest.Mocked<IIdentityConfigRepository>;
  const secretResolver = {
    resolve: jest.fn(async () => SecretValue.create('bind-password')),
  } as unknown as jest.Mocked<ISecretResolverService>;
  const ldapDirectory = {
    isEnabled: jest.fn(() => true),
    resolveGroups: jest.fn(async () => result),
  } as unknown as jest.Mocked<ILdapDirectory>;

  return {
    useCase: new TestLdapProfileUseCase(
      repository,
      secretResolver,
      ldapDirectory,
      {
        decodeAccessToken: jest.fn(() => ({ sub: 'user-1', username: 'admin' })),
      } as unknown as ITokenService,
    ),
  };
}
