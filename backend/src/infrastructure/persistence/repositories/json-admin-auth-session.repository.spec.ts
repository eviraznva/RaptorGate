import { jest } from '@jest/globals';
import { AdminAuthSession } from '../../../domain/entities/admin-auth-session.entity.js';
import { Role } from '../../../domain/enums/role.enum.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import { JsonAdminAuthSessionRepository } from './json-admin-auth-session.repository.js';

describe('JsonAdminAuthSessionRepository', () => {
  it('saves and loads external admin sessions', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({ items: [] })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<void>) => fn()),
    } as unknown as Mutex;
    const repository = new JsonAdminAuthSessionRepository(fileStore, mutex);
    const session = AdminAuthSession.create(
      'session-1',
      'admin',
      'radius',
      'auth-1',
      'external-admin',
      [Role.Admin],
      'refresh-token-hash',
      new Date('2099-05-02T11:00:00.000Z'),
      new Date('2026-05-02T10:00:00.000Z'),
      new Date('2026-05-02T10:00:00.000Z'),
      null,
    );

    await repository.save(session);

    expect(fileStore.writeJsonAtomic).toHaveBeenCalledWith(
      expect.stringContaining('admin_auth_sessions.json'),
      {
        items: [
          {
            id: 'session-1',
            username: 'admin',
            provider: 'radius',
            authProfileId: 'auth-1',
            externalId: 'external-admin',
            roles: ['admin'],
            refreshTokenHash: 'refresh-token-hash',
            refreshTokenExpiry: '2099-05-02T11:00:00.000Z',
            createdAt: '2026-05-02T10:00:00.000Z',
            lastSeenAt: '2026-05-02T10:00:00.000Z',
            revokedAt: null,
          },
        ],
      },
    );
  });

  it('revokes sessions by id', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({
        items: [
          {
            id: 'session-1',
            username: 'admin',
            provider: 'radius',
            authProfileId: 'auth-1',
            externalId: 'external-admin',
            roles: ['admin'],
            refreshTokenHash: 'refresh-token-hash',
            refreshTokenExpiry: '2099-05-02T11:00:00.000Z',
            createdAt: '2026-05-02T10:00:00.000Z',
            lastSeenAt: '2026-05-02T10:00:00.000Z',
            revokedAt: null,
          },
        ],
      })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<void>) => fn()),
    } as unknown as Mutex;
    const repository = new JsonAdminAuthSessionRepository(fileStore, mutex);

    await repository.revoke('session-1', new Date('2026-05-02T10:05:00.000Z'));

    expect((fileStore.writeJsonAtomic as any).mock.calls[0][1].items[0].revokedAt).toBe(
      '2026-05-02T10:05:00.000Z',
    );
  });

  it('purges expired and revoked sessions lazily while reading', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({
        items: [
          {
            id: 'active',
            username: 'admin',
            provider: 'radius',
            authProfileId: 'auth-1',
            externalId: 'external-admin',
            roles: ['admin'],
            refreshTokenHash: 'active-hash',
            refreshTokenExpiry: '2099-05-02T11:00:00.000Z',
            createdAt: '2026-05-02T10:00:00.000Z',
            lastSeenAt: '2026-05-02T10:00:00.000Z',
            revokedAt: null,
          },
          {
            id: 'expired',
            username: 'old',
            provider: 'radius',
            authProfileId: 'auth-1',
            externalId: 'old-admin',
            roles: ['admin'],
            refreshTokenHash: 'expired-hash',
            refreshTokenExpiry: '2000-05-02T11:00:00.000Z',
            createdAt: '2000-05-02T10:00:00.000Z',
            lastSeenAt: '2000-05-02T10:00:00.000Z',
            revokedAt: null,
          },
          {
            id: 'revoked',
            username: 'revoked',
            provider: 'ldap',
            authProfileId: 'auth-2',
            externalId: 'revoked-admin',
            roles: ['viewer'],
            refreshTokenHash: 'revoked-hash',
            refreshTokenExpiry: '2099-05-02T11:00:00.000Z',
            createdAt: '2026-05-02T10:00:00.000Z',
            lastSeenAt: '2026-05-02T10:00:00.000Z',
            revokedAt: '2026-05-02T10:10:00.000Z',
          },
        ],
      })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<unknown>) => fn()),
    } as unknown as Mutex;
    const repository = new JsonAdminAuthSessionRepository(fileStore, mutex);

    const result = await repository.findById('active');

    expect(result?.getId()).toBe('active');
    expect((fileStore.writeJsonAtomic as any).mock.calls[0][1].items).toHaveLength(1);
    expect((fileStore.writeJsonAtomic as any).mock.calls[0][1].items[0].id).toBe('active');
  });
});
