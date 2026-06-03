import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type { IRadiusAuthenticator } from '../ports/radius-authenticator.interface.js';
import type { ISecretResolverService } from '../ports/secret-resolver.service.js';
import type { AuthenticationGroupResolverService } from './authentication-group-resolver.service.js';
import { RadiusAuthenticationProviderService } from './radius-authentication-provider.service.js';

describe('RadiusAuthenticationProviderService', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');

  function auth(): IdentityAuthenticationProfile {
    return IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      true,
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

  function service(radiusResult: Awaited<ReturnType<IRadiusAuthenticator['authenticate']>>) {
    const radiusAuthenticator = {
      authenticate: jest.fn(async () => radiusResult),
    } as unknown as jest.Mocked<IRadiusAuthenticator>;
    const secretResolver = {
      resolve: jest.fn(async () => SecretValue.create('radiussecret')),
    } as unknown as jest.Mocked<ISecretResolverService>;
    const groupResolver = {
      resolve: jest.fn(async () => ({
        groups: ['users'],
        externalId: 'user',
        source: 'radius_vsa',
        diagnostic: 'ok',
      })),
    } as unknown as jest.Mocked<AuthenticationGroupResolverService>;

    return {
      radiusAuthenticator,
      provider: new RadiusAuthenticationProviderService(
        radiusAuthenticator,
        secretResolver,
        groupResolver,
      ),
    };
  }

  it('returns accept with groups from the configured profile', async () => {
    const { provider, radiusAuthenticator } = service({
      kind: 'accept',
      groups: ['users'],
    });

    const result = await provider.authenticate(
      { username: 'user', password: 'pw', sourceIp: '203.0.113.10' },
      {
        kind: 'resolved',
        flow: 'portal',
        authenticationProfile: auth(),
        radiusProfile: radius(),
        ldapProfile: null,
      },
    );

    expect(result.kind).toBe('accept');
    expect(radiusAuthenticator.authenticate).toHaveBeenCalledWith(
      expect.objectContaining({
        callingStationId: '203.0.113.10',
        profile: expect.objectContaining({
          authenticationProtocol: 'pap',
          servers: [
            expect.objectContaining({
              host: '127.0.0.1',
              secret: 'radiussecret',
              priority: 1,
            }),
          ],
        }),
      }),
    );
  });

  it('preserves typed radius attributes on accepted results', async () => {
    const { provider } = service({
      kind: 'accept',
      groups: ['admins'],
      attributes: {
        userGroups: ['admins'],
        adminRole: 'superuser',
        accessDomain: null,
        panoramaAdminRole: null,
        panoramaAccessDomain: null,
        userDomain: null,
        rawDiagnostics: [],
      },
    });

    const result = await provider.authenticate(
      { username: 'user', password: 'pw', sourceIp: '203.0.113.10' },
      {
        kind: 'resolved',
        flow: 'portal',
        authenticationProfile: auth(),
        radiusProfile: radius(),
        ldapProfile: null,
      },
    );

    expect(result).toMatchObject({
      kind: 'accept',
      radiusAttributes: {
        adminRole: 'superuser',
        userGroups: ['admins'],
      },
    });
  });

  it('preserves reject, timeout and error as distinct outcomes', async () => {
    await expect(
      service({ kind: 'reject', reason: 'Access-Reject' }).provider.authenticate(
        { username: 'user', password: 'bad' },
        {
          kind: 'resolved',
          flow: 'portal',
          authenticationProfile: auth(),
          radiusProfile: radius(),
          ldapProfile: null,
        },
      ),
    ).resolves.toMatchObject({ kind: 'reject' });

    await expect(
      service({ kind: 'timeout' }).provider.authenticate(
        { username: 'user', password: 'pw' },
        {
          kind: 'resolved',
          flow: 'portal',
          authenticationProfile: auth(),
          radiusProfile: radius(),
          ldapProfile: null,
        },
      ),
    ).resolves.toMatchObject({ kind: 'timeout' });

    await expect(
      service({ kind: 'error', message: 'ECONNREFUSED' }).provider.authenticate(
        { username: 'user', password: 'pw' },
        {
          kind: 'resolved',
          flow: 'portal',
          authenticationProfile: auth(),
          radiusProfile: radius(),
          ldapProfile: null,
        },
      ),
    ).resolves.toMatchObject({ kind: 'unavailable' });
  });
});
