import type { AuthenticationProviderService } from '../dtos/authentication-engine.dto.js';
import { AuthenticationEngineService } from './authentication-engine.service.js';

describe('AuthenticationEngineService', () => {
  it('routes accepted RADIUS portal authentication through the selected provider', async () => {
    const resolver = {
      resolve: jest.fn(async () => ({
        kind: 'resolved',
        flow: 'portal',
        authenticationProfile: { getProvider: () => 'radius', getId: () => 'auth-1' },
        radiusProfile: { getId: () => 'radius-1' },
        ldapProfile: null,
      })),
    };
    const radiusProvider = {
      authenticate: jest.fn(async () => ({
        kind: 'accept',
        provider: 'radius',
        username: 'user',
        groups: ['users'],
        externalId: 'user',
        sessionTtlSeconds: 1800,
        nasIp: '192.0.2.1',
        calledStationId: 'raptorgate',
        profileId: 'auth-1',
      })),
    } as unknown as AuthenticationProviderService;
    const service = new AuthenticationEngineService(
      resolver as never,
      radiusProvider,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
    );

    const result = await service.authenticate({
      flow: 'portal',
      username: 'user',
      password: 'pw',
      sourceIp: '203.0.113.10',
    });

    expect(result.kind).toBe('accept');
    expect(radiusProvider.authenticate).toHaveBeenCalledWith(
      expect.objectContaining({
        username: 'user',
        sourceIp: '203.0.113.10',
      }),
      expect.objectContaining({
        radiusProfile: expect.anything(),
      }),
    );
  });

  it('returns disabled when admin external authentication has no profile binding', async () => {
    const resolver = {
      resolve: jest.fn(async () => ({
        kind: 'disabled',
        message: 'admin authentication profile is not configured',
      })),
    };
    const service = new AuthenticationEngineService(
      resolver as never,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
    );

    await expect(
      service.authenticate({
        flow: 'admin',
        username: 'admin',
        password: 'pw',
      }),
    ).resolves.toEqual({
      kind: 'disabled',
      message: 'admin authentication profile is not configured',
    });
  });

  it('routes LDAP and local providers explicitly', async () => {
    const resolver = {
      resolve: jest
        .fn()
        .mockResolvedValueOnce({
          kind: 'resolved',
          flow: 'admin',
          authenticationProfile: { getProvider: () => 'ldap', getId: () => 'auth-ldap' },
          radiusProfile: null,
          ldapProfile: { getId: () => 'ldap-1' },
        })
        .mockResolvedValueOnce({
          kind: 'resolved',
          flow: 'admin',
          authenticationProfile: { getProvider: () => 'local', getId: () => 'auth-local' },
          radiusProfile: null,
          ldapProfile: null,
        }),
    };
    const ldapProvider = {
      authenticate: jest.fn(async () => ({
        kind: 'reject',
        provider: 'ldap',
        reason: 'LDAP invalid credentials',
        profileId: 'auth-ldap',
      })),
    } as unknown as AuthenticationProviderService;
    const localProvider = {
      authenticate: jest.fn(async () => ({
        kind: 'reject',
        provider: 'local',
        reason: 'local password rejected',
        profileId: 'auth-local',
      })),
    } as unknown as AuthenticationProviderService;
    const service = new AuthenticationEngineService(
      resolver as never,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
      ldapProvider,
      localProvider,
    );

    await service.authenticate({ flow: 'admin', username: 'admin', password: 'pw' });
    await service.authenticate({ flow: 'admin', username: 'admin', password: 'pw' });

    expect(ldapProvider.authenticate).toHaveBeenCalledTimes(1);
    expect(localProvider.authenticate).toHaveBeenCalledTimes(1);
  });

  it('fails closed for unknown provider types', async () => {
    const resolver = {
      resolve: jest.fn(async () => ({
        kind: 'resolved',
        flow: 'admin',
        authenticationProfile: { getProvider: () => 'bogus', getId: () => 'auth-1' },
        radiusProfile: null,
        ldapProfile: null,
      })),
    };
    const service = new AuthenticationEngineService(
      resolver as never,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
      { authenticate: jest.fn() } as unknown as AuthenticationProviderService,
    );

    await expect(
      service.authenticate({ flow: 'admin', username: 'admin', password: 'pw' }),
    ).rejects.toThrow('unknown authentication provider');
  });
});
