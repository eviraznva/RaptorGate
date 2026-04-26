import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { IpAddressIsInvalidException } from '../../domain/exceptions/ip-address-is-invalid.exception.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { InMemoryIdentitySessionStore } from '../../infrastructure/identity/in-memory-identity-session.store.js';
import { GetIdentitySessionUseCase } from './get-identity-session.use-case.js';

describe('GetIdentitySessionUseCase', () => {
  let store: InMemoryIdentitySessionStore;
  let useCase: GetIdentitySessionUseCase;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
    useCase = new GetIdentitySessionUseCase(store);
  });

  it('returns authenticated=false when no session is bound to the IP', async () => {
    const result = await useCase.execute({ sourceIp: '192.168.10.10' });

    expect(result).toEqual({
      authenticated: false,
      sourceIp: '192.168.10.10',
    });
  });

  it('returns the active session for the calling IP', async () => {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 60_000);
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'user',
        IpAddress.create('192.168.10.10'),
        now,
        expiresAt,
        ['users', 'guests'],
      ),
    );

    const result = await useCase.execute({ sourceIp: '192.168.10.10' });

    expect(result.authenticated).toBe(true);
    expect(result.sessionId).toBe('sess-1');
    expect(result.username).toBe('user');
    expect(result.sourceIp).toBe('192.168.10.10');
    expect(result.groups).toEqual(['users', 'guests']);
    expect(result.expiresAt?.getTime()).toBe(expiresAt.getTime());
  });

  it('treats an expired session as not authenticated', async () => {
    const now = new Date();
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'user',
        IpAddress.create('192.168.10.10'),
        new Date(now.getTime() - 120_000),
        new Date(now.getTime() - 60_000),
      ),
    );

    const result = await useCase.execute({ sourceIp: '192.168.10.10' });

    expect(result).toEqual({
      authenticated: false,
      sourceIp: '192.168.10.10',
    });
  });

  it('rejects invalid sourceIp', async () => {
    await expect(
      useCase.execute({ sourceIp: 'not-an-ip' }),
    ).rejects.toBeInstanceOf(IpAddressIsInvalidException);
  });

  it('does not return a session bound to a different IP', async () => {
    const now = new Date();
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'user',
        IpAddress.create('192.168.10.10'),
        now,
        new Date(now.getTime() + 60_000),
      ),
    );

    const result = await useCase.execute({ sourceIp: '192.168.10.20' });

    expect(result.authenticated).toBe(false);
    expect(result.sourceIp).toBe('192.168.10.20');
  });
});
