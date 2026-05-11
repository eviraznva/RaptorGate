import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import type { IIdentitySessionSyncService } from '../../application/ports/identity-session-sync-service.interface.js';
import { IdentitySessionSweeperService } from './identity-session-sweeper.service.js';
import { InMemoryIdentitySessionStore } from './in-memory-identity-session.store.js';

function makeConfig(intervalMs = 30_000): ConfigService {
  return {
    get: () => intervalMs,
  } as unknown as ConfigService;
}

describe('IdentitySessionSweeperService', () => {
  let store: InMemoryIdentitySessionStore;
  let sync: jest.Mocked<IIdentitySessionSyncService>;
  let sweeper: IdentitySessionSweeperService;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
    sync = {
      upsertIdentitySession: jest.fn<() => Promise<void>>(),
      revokeIdentitySession: jest.fn<() => Promise<boolean>>(),
    };
    sweeper = new IdentitySessionSweeperService(
      makeConfig() as unknown as ConstructorParameters<
        typeof IdentitySessionSweeperService
      >[0],
      store,
      sync,
    );
  });

  afterEach(() => {
    sweeper.onModuleDestroy();
  });

  it('removes expired sessions and calls firewall revoke', async () => {
    const t0 = new Date('2026-04-25T10:00:00Z');
    const tLater = new Date(t0.getTime() + 5_000);

    await store.upsert(
      IdentitySession.create(
        'sess-expired',
        'a',
        IpAddress.create('10.0.0.1'),
        t0,
        new Date(t0.getTime() + 1000),
      ),
    );
    await store.upsert(
      IdentitySession.create(
        'sess-active',
        'b',
        IpAddress.create('10.0.0.2'),
        t0,
        new Date(t0.getTime() + 60_000),
      ),
    );
    sync.revokeIdentitySession.mockResolvedValue(true);

    await sweeper.sweepOnce(tLater);

    expect(sync.revokeIdentitySession).toHaveBeenCalledTimes(1);
    expect(sync.revokeIdentitySession).toHaveBeenCalledWith('10.0.0.1');
    expect(await store.findBySourceIp('10.0.0.1')).toBeNull();
    expect(await store.findBySourceIp('10.0.0.2')).not.toBeNull();
  });

  it('does not stop sweeping after revoke failure and keeps the session for retry', async () => {
    const t0 = new Date('2026-04-25T10:00:00Z');
    const tLater = new Date(t0.getTime() + 5_000);

    await store.upsert(
      IdentitySession.create(
        'sess-a',
        'a',
        IpAddress.create('10.0.0.1'),
        t0,
        new Date(t0.getTime() + 100),
      ),
    );
    await store.upsert(
      IdentitySession.create(
        'sess-b',
        'b',
        IpAddress.create('10.0.0.2'),
        t0,
        new Date(t0.getTime() + 100),
      ),
    );

    sync.revokeIdentitySession
      .mockRejectedValueOnce(new Error('firewall down'))
      .mockResolvedValueOnce(true);

    await sweeper.sweepOnce(tLater);

    expect(sync.revokeIdentitySession).toHaveBeenCalledTimes(2);
    const remaining = await store.listAll();
    expect(remaining.length).toBe(1);
    expect(remaining[0].getId()).toBe('sess-a');

    sync.revokeIdentitySession.mockResolvedValueOnce(true);
    await sweeper.sweepOnce(tLater);

    expect(sync.revokeIdentitySession).toHaveBeenCalledTimes(3);
    expect(await store.listAll()).toEqual([]);
  });
});
