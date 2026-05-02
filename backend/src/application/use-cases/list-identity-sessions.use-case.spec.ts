import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { InMemoryIdentitySessionStore } from '../../infrastructure/identity/in-memory-identity-session.store.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { ListIdentitySessionsUseCase } from './list-identity-sessions.use-case.js';

describe('ListIdentitySessionsUseCase', () => {
  it('returns non-expired runtime identity sessions', async () => {
    const store = new InMemoryIdentitySessionStore();
    const now = new Date();
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'user',
        IpAddress.create('10.0.0.10'),
        new Date(now.getTime() - 1000),
        new Date(now.getTime() + 60_000),
        ['users'],
      ),
    );
    await store.upsert(
      IdentitySession.create(
        'sess-2',
        'guest',
        IpAddress.create('10.0.0.11'),
        new Date(now.getTime() - 120_000),
        new Date(now.getTime() - 60_000),
        ['guests'],
      ),
    );
    const useCase = new ListIdentitySessionsUseCase(store);

    const result = await useCase.execute();

    expect(result.identitySessions).toEqual([
      {
        sessionId: 'sess-1',
        sourceIp: '10.0.0.10',
        username: 'user',
        groups: ['users'],
        createdAt: expect.any(Date),
        expiresAt: expect.any(Date),
      },
    ]);
  });
});
