import { User } from '../../domain/entities/user.entity.js';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import type { IUserRepository } from '../../domain/repositories/user.repository.js';
import type { IPasswordHasher } from '../ports/passowrd-hasher.interface.js';
import { LocalAuthenticationProviderService } from './local-authentication-provider.service.js';

describe('LocalAuthenticationProviderService', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');

  function auth(): IdentityAuthenticationProfile {
    return IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      true,
      'local',
      null,
      null,
      'none',
      1800,
      now,
      now,
      'test',
    );
  }

  function service(passwordValid: boolean, foundUser = true) {
    const userRepository = {
      findByUsername: jest.fn(async () =>
        foundUser
          ? User.create('user-1', 'admin', 'hash', null, null, null, false, false, now, now, [])
          : null,
      ),
    } as unknown as jest.Mocked<IUserRepository>;
    const passwordHasher = {
      compare: jest.fn(async () => passwordValid),
    } as unknown as jest.Mocked<IPasswordHasher>;
    const groupResolver = {
      resolve: jest.fn(async () => ({
        groups: [],
        externalId: 'admin',
        source: 'none',
        diagnostic: 'skipped',
      })),
    };

    return new LocalAuthenticationProviderService(
      userRepository,
      passwordHasher,
      groupResolver as never,
    );
  }

  it('accepts a valid local user', async () => {
    await expect(
      service(true).authenticate(
        { username: 'admin', password: 'local' },
        {
          kind: 'resolved',
          flow: 'admin',
          authenticationProfile: auth(),
          radiusProfile: null,
          ldapProfile: null,
        },
      ),
    ).resolves.toMatchObject({
      kind: 'accept',
      provider: 'local',
      username: 'admin',
    });
  });

  it('rejects wrong password and missing local users', async () => {
    const resolved = {
      kind: 'resolved' as const,
      flow: 'admin' as const,
      authenticationProfile: auth(),
      radiusProfile: null,
      ldapProfile: null,
    };

    await expect(
      service(false).authenticate(
        { username: 'admin', password: 'bad' },
        resolved,
      ),
    ).resolves.toMatchObject({ kind: 'reject' });

    await expect(
      service(false, false).authenticate(
        { username: 'admin', password: 'bad' },
        resolved,
      ),
    ).resolves.toMatchObject({ kind: 'reject' });
  });
});
