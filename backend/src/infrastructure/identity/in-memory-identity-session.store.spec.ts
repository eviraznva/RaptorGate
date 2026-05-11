import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { InMemoryIdentitySessionStore } from './in-memory-identity-session.store.js';

function makeSession(
  ip: string,
  username: string,
  expiresInMs: number,
  now: Date = new Date(),
): IdentitySession {
  return IdentitySession.create(
    `sess-${ip}`,
    username,
    IpAddress.create(ip),
    now,
    new Date(now.getTime() + expiresInMs),
  );
}

describe('InMemoryIdentitySessionStore', () => {
  let store: InMemoryIdentitySessionStore;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
  });

  it('upsert and findBySourceIp work for a new session', async () => {
    await store.upsert(makeSession('192.168.10.10', 'user', 60_000));
    const found = await store.findBySourceIp('192.168.10.10');
    expect(found?.getUsername()).toBe('user');
  });

  it('upsert replaces the session for the same IP', async () => {
    await store.upsert(makeSession('192.168.10.10', 'old', 60_000));
    await store.upsert(makeSession('192.168.10.10', 'new', 60_000));

    const found = await store.findBySourceIp('192.168.10.10');
    expect(found?.getUsername()).toBe('new');
    expect((await store.listAll()).length).toBe(1);
  });

  it('removeBySourceIp returns the removed session or null', async () => {
    await store.upsert(makeSession('10.0.0.1', 'a', 60_000));

    const removed = await store.removeBySourceIp('10.0.0.1');
    expect(removed?.getUsername()).toBe('a');

    const missing = await store.removeBySourceIp('10.0.0.99');
    expect(missing).toBeNull();
  });

  it('peekExpired returns expired sessions without removing them from store', async () => {
    const now = new Date('2026-04-25T10:00:00Z');
    await store.upsert(makeSession('10.0.0.1', 'expired1', -1000, now));
    await store.upsert(makeSession('10.0.0.2', 'active', 60_000, now));
    await store.upsert(makeSession('10.0.0.3', 'expired2', 0, now));

    const expired = await store.peekExpired(now);
    const expiredIps = expired.map((s) => s.getSourceIp().getValue).sort();
    expect(expiredIps).toEqual(['10.0.0.1', '10.0.0.3']);

    const remaining = await store.listAll();
    expect(remaining.length).toBe(3);
  });
});
