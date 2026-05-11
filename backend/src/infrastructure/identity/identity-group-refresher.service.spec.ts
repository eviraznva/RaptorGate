import { jest } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import type { IIdentitySessionSyncService } from '../../application/ports/identity-session-sync-service.interface.js';
import type { AuthenticationGroupResolverService } from '../../application/services/authentication-group-resolver.service.js';
import type { AuthenticationProfileResolverService } from '../../application/services/authentication-profile-resolver.service.js';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { IdentityGroupRefresherService } from './identity-group-refresher.service.js';
import { InMemoryIdentitySessionStore } from './in-memory-identity-session.store.js';

function makeConfig(): ConfigService {
  const map = new Map<string, unknown>([
    ['IDENTITY_GROUP_REFRESH_INTERVAL_MS', 0],
  ]);
  return { get: (key: string) => map.get(key) } as unknown as ConfigService;
}

const resolvedPortalProfile = {
  kind: 'resolved',
  flow: 'portal',
  authenticationProfile: { getId: () => 'auth-1' },
  radiusProfile: null,
  ldapProfile: { getId: () => 'ldap-1' },
};

describe('IdentityGroupRefresherService', () => {
  let store: InMemoryIdentitySessionStore;
  let sync: jest.Mocked<IIdentitySessionSyncService>;
  let profileResolver: jest.Mocked<Pick<AuthenticationProfileResolverService, 'resolve'>>;
  let groupResolver: jest.Mocked<Pick<AuthenticationGroupResolverService, 'resolve'>>;
  let refresher: IdentityGroupRefresherService;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
    sync = {
      upsertIdentitySession: jest.fn<() => Promise<void>>(),
      revokeIdentitySession: jest.fn<() => Promise<boolean>>(),
    };
    profileResolver = {
      resolve: jest.fn(async () => resolvedPortalProfile),
    } as unknown as jest.Mocked<Pick<AuthenticationProfileResolverService, 'resolve'>>;
    groupResolver = {
      resolve: jest.fn(),
    } as unknown as jest.Mocked<Pick<AuthenticationGroupResolverService, 'resolve'>>;
    refresher = new IdentityGroupRefresherService(
      makeConfig() as unknown as ConstructorParameters<
        typeof IdentityGroupRefresherService
      >[0],
      store,
      sync,
      profileResolver as unknown as AuthenticationProfileResolverService,
      groupResolver as unknown as AuthenticationGroupResolverService,
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
    groupResolver.resolve.mockResolvedValue({
      groups: [],
      source: 'none',
      externalId: 'user',
      diagnostic: 'disabled',
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
    groupResolver.resolve.mockResolvedValue({
      groups: ['admins'],
      source: 'ldap',
      externalId: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      diagnostic: 'ok',
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
        '198.51.100.10',
        'profile-nas',
        'uid=admin,ou=users,dc=raptorgate,dc=local',
      ),
    );
    groupResolver.resolve.mockResolvedValue({
      groups: ['admins', 'auditors'],
      source: 'ldap',
      externalId: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      diagnostic: 'ok',
    });
    sync.upsertIdentitySession.mockResolvedValue(undefined);
    const persistSpy = jest.spyOn(store, 'upsert');

    await refresher.refreshOnce();

    expect(profileResolver.resolve).toHaveBeenCalledWith('portal');
    expect(groupResolver.resolve).toHaveBeenCalledWith(
      resolvedPortalProfile,
      'admin',
      [],
    );
    expect(sync.upsertIdentitySession).toHaveBeenCalledTimes(1);
    const payload = sync.upsertIdentitySession.mock.calls[0][0];
    expect(payload.id).toBe('sess-1');
    expect(payload.groups).toEqual(['admins', 'auditors']);
    expect(payload.nasIp).toBe('198.51.100.10');
    expect(payload.calledStationId).toBe('profile-nas');
    expect(payload.identityUserId).toBe(
      'uid=admin,ou=users,dc=raptorgate,dc=local',
    );

    const live = await store.findBySourceIp('10.0.0.1');
    expect(live?.getGroups()).toEqual(['admins', 'auditors']);
    expect(live?.getId()).toBe('sess-1');
    expect(persistSpy).toHaveBeenCalledWith(live);
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
    groupResolver.resolve.mockResolvedValue({
      groups: ['admins', 'auditors'],
      source: 'ldap',
      externalId: 'uid=admin,ou=users,dc=raptorgate,dc=local',
      diagnostic: 'ok',
    });
    sync.upsertIdentitySession.mockRejectedValue(new Error('firewall down'));

    await refresher.refreshOnce();

    const live = await store.findBySourceIp('10.0.0.1');
    expect(live?.getGroups()).toEqual(['admins']);
  });
});
