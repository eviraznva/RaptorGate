import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type { ILdapAuthenticator } from '../ports/ldap-authenticator.interface.js';
import type { ISecretResolverService } from '../ports/secret-resolver.service.js';
import { LdapAuthenticationProviderService } from './ldap-authentication-provider.service.js';

describe('LdapAuthenticationProviderService', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');

  function auth(): IdentityAuthenticationProfile {
    return IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      true,
      'ldap',
      null,
      'ldap-1',
      'ldap',
      1800,
      now,
      now,
      'test',
    );
  }

  function ldap(): LdapServerProfile {
    return LdapServerProfile.create(
      'ldap-1',
      'LDAP',
      null,
      true,
      '127.0.0.1',
      389,
      'disabled',
      'cn=admin,dc=raptorgate,dc=local',
      'secret://identity/ldap/default',
      'ou=users,dc=raptorgate,dc=local',
      'uid',
      'ou=groups,dc=raptorgate,dc=local',
      'memberUid',
      'cn',
      500,
      300,
      now,
      now,
      'test',
    );
  }

  function service(result: Awaited<ReturnType<ILdapAuthenticator['authenticate']>>) {
    const ldapAuthenticator = {
      authenticate: jest.fn(async () => result),
    } as unknown as jest.Mocked<ILdapAuthenticator>;
    const secretResolver = {
      resolve: jest.fn(async () => SecretValue.create('admin')),
    } as unknown as jest.Mocked<ISecretResolverService>;
    return {
      ldapAuthenticator,
      provider: new LdapAuthenticationProviderService(
        ldapAuthenticator,
        secretResolver,
      ),
    };
  }

  it('returns accept with LDAP DN and groups', async () => {
    const { provider, ldapAuthenticator } = service({
      kind: 'accept',
      userDn: 'uid=user,ou=users,dc=raptorgate,dc=local',
      groups: ['users'],
    });

    const result = await provider.authenticate(
      { username: 'user', password: 'pw' },
      {
        kind: 'resolved',
        flow: 'admin',
        authenticationProfile: auth(),
        radiusProfile: null,
        ldapProfile: ldap(),
      },
    );

    expect(result).toMatchObject({
      kind: 'accept',
      provider: 'ldap',
      externalId: 'uid=user,ou=users,dc=raptorgate,dc=local',
      groups: ['users'],
    });
    expect(ldapAuthenticator.authenticate).toHaveBeenCalledWith(
      expect.objectContaining({
        username: 'user',
        options: expect.objectContaining({
          bindPassword: 'admin',
          userFilterAttribute: 'uid',
        }),
      }),
    );
  });

  it('preserves LDAP reject, timeout and transport errors as distinct outcomes', async () => {
    const resolved = {
      kind: 'resolved' as const,
      flow: 'admin' as const,
      authenticationProfile: auth(),
      radiusProfile: null,
      ldapProfile: ldap(),
    };

    await expect(
      service({ kind: 'reject', reason: 'LDAP invalid credentials' }).provider.authenticate(
        { username: 'user', password: 'bad' },
        resolved,
      ),
    ).resolves.toMatchObject({ kind: 'reject' });

    await expect(
      service({ kind: 'timeout', message: 'LDAP socket timeout' }).provider.authenticate(
        { username: 'user', password: 'pw' },
        resolved,
      ),
    ).resolves.toMatchObject({ kind: 'timeout' });

    await expect(
      service({ kind: 'error', message: 'ECONNREFUSED' }).provider.authenticate(
        { username: 'user', password: 'pw' },
        resolved,
      ),
    ).resolves.toMatchObject({ kind: 'unavailable' });
  });
});
