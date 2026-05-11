import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import type {
  IIdentitySessionSyncService,
  IdentitySessionSyncPayload,
} from '../../application/ports/identity-session-sync-service.interface.js';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { InMemoryIdentitySessionStore } from './in-memory-identity-session.store.js';
import { IdentitySessionReplayService } from './identity-session-replay.service.js';

function makeConfig(intervalMs = 30_000): ConfigService {
  return {
    get: () => intervalMs,
  } as unknown as ConfigService;
}

describe('IdentitySessionReplayService', () => {
  let store: InMemoryIdentitySessionStore;
  let sync: jest.Mocked<IIdentitySessionSyncService>;
  let replay: IdentitySessionReplayService;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
    sync = {
      upsertIdentitySession: jest.fn<(session: IdentitySessionSyncPayload) => Promise<void>>(
        async () => undefined,
      ),
      revokeIdentitySession: jest.fn<(ipAddress: string) => Promise<boolean>>(
        async () => false,
      ),
    };
    replay = new IdentitySessionReplayService(
      makeConfig() as unknown as ConstructorParameters<
        typeof IdentitySessionReplayService
      >[0],
      store,
      sync,
    );
  });

  afterEach(() => {
    replay.onModuleDestroy();
  });

  it('replays active sessions to firewall', async () => {
    const now = new Date('2026-05-02T10:00:00.000Z');
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'alice',
        IpAddress.create('10.0.0.10'),
        now,
        new Date('2026-05-02T10:30:00.000Z'),
        ['admins'],
        '192.168.20.254',
        'raptorgate',
        'user-1',
        '00:11:22:33:44:55',
      ),
    );

    await replay.replayOnce(now);

    expect(sync.upsertIdentitySession).toHaveBeenCalledWith({
      id: 'sess-1',
      identityUserId: 'user-1',
      radiusUsername: 'alice',
      macAddress: '00:11:22:33:44:55',
      ipAddress: '10.0.0.10',
      nasIp: '192.168.20.254',
      calledStationId: 'raptorgate',
      authenticatedAt: now,
      expiresAt: new Date('2026-05-02T10:30:00.000Z'),
      groups: ['admins'],
    });
  });

  it('skips expired sessions during replay', async () => {
    const now = new Date('2026-05-02T10:00:00.000Z');
    await store.upsert(
      IdentitySession.create(
        'sess-expired',
        'alice',
        IpAddress.create('10.0.0.10'),
        new Date('2026-05-02T09:00:00.000Z'),
        now,
      ),
    );

    await replay.replayOnce(now);

    expect(sync.upsertIdentitySession).not.toHaveBeenCalled();
  });

  it('continues replay after one firewall sync failure', async () => {
    const now = new Date('2026-05-02T10:00:00.000Z');
    await store.upsert(
      IdentitySession.create(
        'sess-a',
        'alice',
        IpAddress.create('10.0.0.10'),
        now,
        new Date('2026-05-02T10:30:00.000Z'),
      ),
    );
    await store.upsert(
      IdentitySession.create(
        'sess-b',
        'bob',
        IpAddress.create('10.0.0.11'),
        now,
        new Date('2026-05-02T10:30:00.000Z'),
      ),
    );
    sync.upsertIdentitySession
      .mockRejectedValueOnce(new Error('firewall down'))
      .mockResolvedValueOnce(undefined);

    await replay.replayOnce(now);

    expect(sync.upsertIdentitySession).toHaveBeenCalledTimes(2);
  });

  it('skips sessions removed after replay snapshot', async () => {
    const now = new Date('2026-05-02T10:00:00.000Z');
    const session = IdentitySession.create(
      'sess-stale',
      'alice',
      IpAddress.create('10.0.0.10'),
      now,
      new Date('2026-05-02T10:30:00.000Z'),
    );
    jest.spyOn(store, 'listAll').mockResolvedValue([session]);

    await replay.replayOnce(now);

    expect(sync.upsertIdentitySession).not.toHaveBeenCalled();
  });

  it('does not run overlapping replay passes', async () => {
    const now = new Date('2026-05-02T10:00:00.000Z');
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'alice',
        IpAddress.create('10.0.0.10'),
        now,
        new Date('2026-05-02T10:30:00.000Z'),
      ),
    );
    let release!: () => void;
    const pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    sync.upsertIdentitySession.mockReturnValueOnce(pending);

    const first = replay.replayOnce(now);
    const second = replay.replayOnce(now);
    await second;
    release();
    await first;

    expect(sync.upsertIdentitySession).toHaveBeenCalledTimes(1);
  });
});
