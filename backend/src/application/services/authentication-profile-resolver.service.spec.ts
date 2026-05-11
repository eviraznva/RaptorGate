import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import type { IIdentityConfigRepository } from '../../domain/repositories/identity-config.repository.js';
import { AuthenticationProfileResolverService } from './authentication-profile-resolver.service.js';

describe('AuthenticationProfileResolverService', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');

  function radius(): RadiusServerProfile {
    return RadiusServerProfile.create(
      'radius-1',
      'Radius',
      null,
      true,
      '127.0.0.1',
      1812,
      'secret://identity/radius/default',
      500,
      1,
      '192.0.2.1',
      'raptorgate',
      null,
      now,
      now,
      'test',
    );
  }

  function auth(isActive = true): IdentityAuthenticationProfile {
    return IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      isActive,
      'radius',
      'radius-1',
      null,
      'radius_vsa',
      1800,
      now,
      now,
      'test',
    );
  }

  function repo(config: IdentityConfiguration): IIdentityConfigRepository {
    return {
      exists: jest.fn(),
      find: jest.fn(async () => config),
      save: jest.fn(),
      overwrite: jest.fn(),
      mutate: jest.fn(),
    } as unknown as IIdentityConfigRepository;
  }

  it('resolves the portal authentication profile from identity settings', async () => {
    const service = new AuthenticationProfileResolverService(
      repo(
        IdentityConfiguration.create(
          [radius()],
          [],
          [auth()],
          IdentitySettings.create('auth-1', null, now, 'test'),
        ),
      ),
    );

    const result = await service.resolve('portal');

    expect(result.kind).toBe('resolved');
    if (result.kind !== 'resolved') throw new Error('expected resolved');
    expect(result.authenticationProfile.getId()).toBe('auth-1');
    expect(result.radiusProfile?.getId()).toBe('radius-1');
  });

  it('returns disabled when admin authentication has no active binding', async () => {
    const service = new AuthenticationProfileResolverService(
      repo(
        IdentityConfiguration.create(
          [radius()],
          [],
          [auth()],
          IdentitySettings.create('auth-1', null, now, 'test'),
        ),
      ),
    );

    await expect(service.resolve('admin')).resolves.toEqual({
      kind: 'disabled',
      message: 'admin authentication profile is not configured',
    });
  });

  it('reports inactive authentication profiles as misconfigured', async () => {
    const service = new AuthenticationProfileResolverService(
      repo(
        IdentityConfiguration.create(
          [radius()],
          [],
          [auth(false)],
          IdentitySettings.create('auth-1', null, now, 'test'),
        ),
      ),
    );

    await expect(service.resolve('portal')).resolves.toMatchObject({
      kind: 'misconfigured',
      message: expect.stringContaining('inactive'),
    });
  });
});
