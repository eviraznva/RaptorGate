import { AuthenticationMisconfiguredException } from '../../domain/exceptions/authentication-misconfigured.exception.js';
import { AuthenticationRejectedException } from '../../domain/exceptions/authentication-rejected.exception.js';
import { AuthenticationUnavailableException } from '../../domain/exceptions/authentication-unavailable.exception.js';
import { IpAddressIsInvalidException } from '../../domain/exceptions/ip-address-is-invalid.exception.js';
import { InMemoryIdentitySessionStore } from '../../infrastructure/identity/in-memory-identity-session.store.js';
import type {
  IIdentitySessionSyncService,
  IdentitySessionSyncPayload,
} from '../ports/identity-session-sync-service.interface.js';
import type { AuthenticationEngineService } from '../services/authentication-engine.service.js';
import { AuthenticateIdentityUseCase } from './authenticate-identity.use-case.js';

describe('AuthenticateIdentityUseCase', () => {
  let store: InMemoryIdentitySessionStore;
  let sync: jest.Mocked<IIdentitySessionSyncService>;
  let authenticationEngine: jest.Mocked<AuthenticationEngineService>;
  let useCase: AuthenticateIdentityUseCase;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
    sync = {
      upsertIdentitySession: jest.fn<Promise<void>, [IdentitySessionSyncPayload]>(
        async () => undefined,
      ),
      revokeIdentitySession: jest.fn<Promise<boolean>, [string]>(
        async () => false,
      ),
    };
    authenticationEngine = {
      authenticate: jest.fn(),
    } as unknown as jest.Mocked<AuthenticationEngineService>;
    useCase = new AuthenticateIdentityUseCase(store, sync, authenticationEngine);
  });

  it('creates a portal identity session from the configured authentication profile', async () => {
    authenticationEngine.authenticate.mockResolvedValue({
      kind: 'accept',
      provider: 'radius',
      username: 'admin',
      groups: ['admins'],
      groupSource: 'ldap',
      externalId: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      sessionTtlSeconds: 1800,
      nasIp: '192.168.20.254',
      calledStationId: 'raptorgate-backend',
      profileId: 'auth-1',
    });
    sync.upsertIdentitySession.mockResolvedValue(undefined);

    const result = await useCase.execute({
      username: 'admin',
      password: 'admin123',
      sourceIp: '192.168.10.10',
    });

    expect(result.username).toBe('admin');
    expect(authenticationEngine.authenticate).toHaveBeenCalledWith({
      flow: 'portal',
      username: 'admin',
      password: 'admin123',
      sourceIp: '192.168.10.10',
    });

    const stored = await store.findBySourceIp('192.168.10.10');
    expect(stored?.getGroups()).toEqual(['admins']);

    const payload = sync.upsertIdentitySession.mock.calls[0][0];
    expect(payload.groups).toEqual(['admins']);
    expect(payload.identityUserId).toBe(
      'uid=admin,ou=users,dc=raptorgate,dc=local',
    );
    expect(payload.nasIp).toBe('192.168.20.254');
    expect(payload.calledStationId).toBe('raptorgate-backend');
  });

  it('does not create a session after rejected authentication', async () => {
    authenticationEngine.authenticate.mockResolvedValue({
      kind: 'reject',
      provider: 'radius',
      reason: 'bad-creds',
      profileId: 'auth-1',
    });

    await expect(
      useCase.execute({
        username: 'user',
        password: 'wrong',
        sourceIp: '192.168.10.10',
      }),
    ).rejects.toBeInstanceOf(AuthenticationRejectedException);

    expect(await store.findBySourceIp('192.168.10.10')).toBeNull();
    expect(sync.upsertIdentitySession).not.toHaveBeenCalled();
  });

  it('maps provider timeout to unavailable without creating a session', async () => {
    authenticationEngine.authenticate.mockResolvedValue({
      kind: 'timeout',
      provider: 'radius',
      message: 'RADIUS request timed out',
      profileId: 'auth-1',
    });

    await expect(
      useCase.execute({
        username: 'user',
        password: 'user123',
        sourceIp: '192.168.10.10',
      }),
    ).rejects.toBeInstanceOf(AuthenticationUnavailableException);

    expect(await store.findBySourceIp('192.168.10.10')).toBeNull();
    expect(sync.upsertIdentitySession).not.toHaveBeenCalled();
  });

  it('maps misconfiguration to a service-level exception', async () => {
    authenticationEngine.authenticate.mockResolvedValue({
      kind: 'misconfigured',
      message: 'portal authentication profile is not configured',
    });

    await expect(
      useCase.execute({
        username: 'user',
        password: 'user123',
        sourceIp: '192.168.10.10',
      }),
    ).rejects.toBeInstanceOf(AuthenticationMisconfiguredException);
  });

  it('does not call the engine when sourceIp is invalid', async () => {
    await expect(
      useCase.execute({
        username: 'user',
        password: 'user123',
        sourceIp: 'not-an-ip',
      }),
    ).rejects.toBeInstanceOf(IpAddressIsInvalidException);

    expect(authenticationEngine.authenticate).not.toHaveBeenCalled();
  });

  it('does not store the session when firewall sync fails', async () => {
    authenticationEngine.authenticate.mockResolvedValue({
      kind: 'accept',
      provider: 'radius',
      username: 'user',
      groups: [],
      groupSource: 'none',
      externalId: 'user',
      sessionTtlSeconds: 1800,
      nasIp: '192.168.20.254',
      calledStationId: 'raptorgate-backend',
      profileId: 'auth-1',
    });
    sync.upsertIdentitySession.mockRejectedValue(
      new Error('firewall unreachable'),
    );

    await expect(
      useCase.execute({
        username: 'user',
        password: 'user123',
        sourceIp: '192.168.10.10',
      }),
    ).rejects.toThrow('firewall unreachable');

    expect(await store.findBySourceIp('192.168.10.10')).toBeNull();
  });
});
