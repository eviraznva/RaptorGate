import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import { IpAddressIsInvalidException } from '../../domain/exceptions/ip-address-is-invalid.exception.js';
import { RadiusAccessRejectedException } from '../../domain/exceptions/radius-access-rejected.exception.js';
import { RadiusUnavailableException } from '../../domain/exceptions/radius-unavailable.exception.js';
import { InMemoryIdentitySessionStore } from '../../infrastructure/identity/in-memory-identity-session.store.js';
import type { IIdentitySessionSyncService } from '../ports/identity-session-sync-service.interface.js';
import type {
  IRadiusAuthenticator,
  RadiusAuthResult,
} from '../ports/radius-authenticator.interface.js';
import { AuthenticateIdentityUseCase } from './authenticate-identity.use-case.js';

function makeConfig(): ConfigService {
  const map = new Map<string, unknown>([
    ['IDENTITY_SESSION_TTL_SECONDS', 1800],
    ['RADIUS_NAS_IP', '192.168.20.254'],
    ['RADIUS_NAS_IDENTIFIER', 'raptorgate-backend'],
  ]);
  return { get: (key: string) => map.get(key) } as unknown as ConfigService;
}

describe('AuthenticateIdentityUseCase', () => {
  let store: InMemoryIdentitySessionStore;
  let radius: jest.Mocked<IRadiusAuthenticator>;
  let sync: jest.Mocked<IIdentitySessionSyncService>;
  let useCase: AuthenticateIdentityUseCase;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
    radius = { authenticate: jest.fn() };
    sync = {
      upsertIdentitySession: jest.fn<() => Promise<void>>(),
      revokeIdentitySession: jest.fn<() => Promise<boolean>>(),
    };
    useCase = new AuthenticateIdentityUseCase(
      radius,
      store,
      sync,
      makeConfig() as unknown as ConstructorParameters<
        typeof AuthenticateIdentityUseCase
      >[3],
    );
  });

  it('creates a session and sends firewall upsert after Access-Accept', async () => {
    radius.authenticate.mockResolvedValue({ kind: 'accept' } as RadiusAuthResult);
    sync.upsertIdentitySession.mockResolvedValue(undefined);

    const result = await useCase.execute({
      username: 'user',
      password: 'user123',
      sourceIp: '192.168.10.10',
    });

    expect(result.username).toBe('user');
    expect(result.sourceIp).toBe('192.168.10.10');
    expect(result.expiresAt.getTime()).toBeGreaterThan(
      result.authenticatedAt.getTime(),
    );

    const stored = await store.findBySourceIp('192.168.10.10');
    expect(stored).not.toBeNull();
    expect(stored?.getUsername()).toBe('user');

    expect(sync.upsertIdentitySession).toHaveBeenCalledTimes(1);
    const payload = sync.upsertIdentitySession.mock.calls[0][0];
    expect(payload.ipAddress).toBe('192.168.10.10');
    expect(payload.radiusUsername).toBe('user');
  });

  it('does not create a session or call upsert after Access-Reject', async () => {
    radius.authenticate.mockResolvedValue({
      kind: 'reject',
      reason: 'bad-creds',
    } as RadiusAuthResult);

    await expect(
      useCase.execute({
        username: 'user',
        password: 'wrong',
        sourceIp: '192.168.10.10',
      }),
    ).rejects.toBeInstanceOf(RadiusAccessRejectedException);

    expect(await store.findBySourceIp('192.168.10.10')).toBeNull();
    expect(sync.upsertIdentitySession).not.toHaveBeenCalled();
  });

  it('returns a clear error and does not create a session on RADIUS timeout', async () => {
    radius.authenticate.mockResolvedValue({ kind: 'timeout' } as RadiusAuthResult);

    await expect(
      useCase.execute({
        username: 'user',
        password: 'user123',
        sourceIp: '192.168.10.10',
      }),
    ).rejects.toMatchObject({
      name: 'RadiusUnavailableException',
      message: expect.stringMatching(/timeout/i),
    });

    expect(await store.findBySourceIp('192.168.10.10')).toBeNull();
    expect(sync.upsertIdentitySession).not.toHaveBeenCalled();
  });

  it('returns a 503-mappable exception on RADIUS connection error', async () => {
    radius.authenticate.mockResolvedValue({
      kind: 'error',
      message: 'ECONNREFUSED',
    } as RadiusAuthResult);

    await expect(
      useCase.execute({
        username: 'user',
        password: 'user123',
        sourceIp: '192.168.10.10',
      }),
    ).rejects.toBeInstanceOf(RadiusUnavailableException);
  });

  it('does not call RADIUS when sourceIp is invalid', async () => {
    await expect(
      useCase.execute({
        username: 'user',
        password: 'user123',
        sourceIp: 'not-an-ip',
      }),
    ).rejects.toBeInstanceOf(IpAddressIsInvalidException);

    expect(radius.authenticate).not.toHaveBeenCalled();
  });

  it('does not store the session when firewall sync fails', async () => {
    radius.authenticate.mockResolvedValue({ kind: 'accept' } as RadiusAuthResult);
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

  it('keeps the previous session for the IP when new session sync fails', async () => {
    radius.authenticate.mockResolvedValue({ kind: 'accept' } as RadiusAuthResult);
    sync.upsertIdentitySession.mockResolvedValueOnce(undefined);

    const first = await useCase.execute({
      username: 'old-user',
      password: 'pw',
      sourceIp: '10.0.0.5',
    });

    sync.upsertIdentitySession.mockRejectedValueOnce(
      new Error('firewall unreachable'),
    );

    await expect(
      useCase.execute({
        username: 'new-user',
        password: 'pw',
        sourceIp: '10.0.0.5',
      }),
    ).rejects.toThrow('firewall unreachable');

    const stored = await store.findBySourceIp('10.0.0.5');
    expect(stored?.getUsername()).toBe('old-user');
    expect(stored?.getId()).toBe(first.sessionId);
  });

  it('replaces the previous session on second login from the same IP', async () => {
    radius.authenticate.mockResolvedValue({ kind: 'accept' } as RadiusAuthResult);
    sync.upsertIdentitySession.mockResolvedValue(undefined);

    await useCase.execute({
      username: 'user-a',
      password: 'pw',
      sourceIp: '10.0.0.5',
    });
    const second = await useCase.execute({
      username: 'user-b',
      password: 'pw',
      sourceIp: '10.0.0.5',
    });

    const stored = await store.findBySourceIp('10.0.0.5');
    expect(stored?.getUsername()).toBe('user-b');
    expect(stored?.getId()).toBe(second.sessionId);
    expect(sync.upsertIdentitySession).toHaveBeenCalledTimes(2);
  });

  it('passes sourceIp to RADIUS as callingStationId instead of body data', async () => {
    radius.authenticate.mockResolvedValue({ kind: 'accept' } as RadiusAuthResult);
    sync.upsertIdentitySession.mockResolvedValue(undefined);

    await useCase.execute({
      username: 'user',
      password: 'pw',
      sourceIp: '203.0.113.7',
    });

    expect(radius.authenticate).toHaveBeenCalledWith({
      username: 'user',
      password: 'pw',
      callingStationId: '203.0.113.7',
    });
  });
});
