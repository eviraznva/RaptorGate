import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import type { IIdentitySessionSyncService } from '../../application/ports/identity-session-sync-service.interface.js';
import type { IdentityGroupResolverService } from '../../application/services/identity-group-resolver.service.js';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { IdentityGroupRefresherService } from './identity-group-refresher.service.js';
import { InMemoryIdentitySessionStore } from './in-memory-identity-session.store.js';

function makeConfig(): ConfigService {
  const map = new Map<string, unknown>([
    ['IDENTITY_GROUP_REFRESH_INTERVAL_MS', 0],
    ['RADIUS_NAS_IP', '192.168.20.254'],
    ['RADIUS_NAS_IDENTIFIER', 'raptorgate-backend'],
  ]);
  return { get: (key: string) => map.get(key) } as unknown as ConfigService;
}

describe('IdentityGroupRefresherService', () => {
  let store: InMemoryIdentitySessionStore;
  let sync: jest.Mocked<IIdentitySessionSyncService>;
  let resolver: jest.Mocked<
    Pick<IdentityGroupResolverService, 'resolve' | 'invalidate'>
  >;
  let refresher: IdentityGroupRefresherService;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
    sync = {
      upsertIdentitySession: jest.fn<() => Promise<void>>(),
      revokeIdentitySession: jest.fn<() => Promise<boolean>>(),
    };
    resolver = {
      resolve: jest.fn(),
      invalidate: jest.fn(),
    } as unknown as jest.Mocked<
      Pick<IdentityGroupResolverService, 'resolve' | 'invalidate'>
    >;
    refresher = new IdentityGroupRefresherService(
      makeConfig() as unknown as ConstructorParameters<
        typeof IdentityGroupRefresherService
      >[0],
      store,
      sync,
      resolver as unknown as IdentityGroupResolverService,
    );
  });

  afterEach(() => {
    refresher.onModuleDestroy();
  });

  it('pomija sesje gdy LDAP wyłaczone albo brak grup', async () => {
    const t0 = new Date('2026-04-25T10:00:00Z');
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'user',
        IpAddress.create('10.0.0.1'),
        t0,
        new Date(t0.getTime() + 60_000),
        ['users'],
      ),
    );
    resolver.resolve.mockResolvedValue({
      groups: [],
      source: 'none',
      externalId: 'user',
      ldapDiagnostic: 'disabled',
    });

    await refresher.refreshOnce();

    expect(sync.upsertIdentitySession).not.toHaveBeenCalled();
  });

  it('nie wysyla upsertu gdy grupy sie nie zmienily', async () => {
    const t0 = new Date('2026-04-25T10:00:00Z');
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'admin',
        IpAddress.create('10.0.0.1'),
        t0,
        new Date(t0.getTime() + 60_000),
        ['admins'],
      ),
    );
    resolver.resolve.mockResolvedValue({
      groups: ['admins'],
      source: 'ldap',
      externalId: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      ldapDiagnostic: 'ok',
    });

    await refresher.refreshOnce();

    expect(sync.upsertIdentitySession).not.toHaveBeenCalled();
  });

  it('pcha nowe grupy do firewalla i podmienia je w sesji bez relogowania', async () => {
    const t0 = new Date('2026-04-25T10:00:00Z');
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'admin',
        IpAddress.create('10.0.0.1'),
        t0,
        new Date(t0.getTime() + 60_000),
        ['admins'],
      ),
    );
    resolver.resolve.mockResolvedValue({
      groups: ['admins', 'auditors'],
      source: 'ldap',
      externalId: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      ldapDiagnostic: 'ok',
    });
    sync.upsertIdentitySession.mockResolvedValue(undefined);

    await refresher.refreshOnce();

    expect(sync.upsertIdentitySession).toHaveBeenCalledTimes(1);
    const payload = sync.upsertIdentitySession.mock.calls[0][0];
    expect(payload.id).toBe('sess-1');
    expect(payload.groups).toEqual(['admins', 'auditors']);
    expect(payload.identityUserId).toBe(
      'uid=admin,ou=users,dc=raptorgate,dc=local',
    );

    const live = await store.findBySourceIp('10.0.0.1');
    expect(live?.getGroups()).toEqual(['admins', 'auditors']);
    expect(live?.getId()).toBe('sess-1');
  });

  it('nie podmienia grup w sesji gdy upsert do firewalla zawiedzie', async () => {
    const t0 = new Date('2026-04-25T10:00:00Z');
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'admin',
        IpAddress.create('10.0.0.1'),
        t0,
        new Date(t0.getTime() + 60_000),
        ['admins'],
      ),
    );
    resolver.resolve.mockResolvedValue({
      groups: ['admins', 'auditors'],
      source: 'ldap',
      externalId: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      ldapDiagnostic: 'ok',
    });
    sync.upsertIdentitySession.mockRejectedValue(new Error('firewall down'));

    await refresher.refreshOnce();

    const live = await store.findBySourceIp('10.0.0.1');
    expect(live?.getGroups()).toEqual(['admins']);
  });
});
