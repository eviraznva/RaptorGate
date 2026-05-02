import { jest } from '@jest/globals';
import { IdentitySession } from '../../../domain/entities/identity-session.entity.js';
import { IpAddress } from '../../../domain/value-objects/ip-address.vo.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import { JsonIdentitySessionStore } from './json-identity-session.store.js';

describe('JsonIdentitySessionStore', () => {
  it('persists identity sessions with replay fields', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({ items: [] })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<unknown>) => fn()),
    } as unknown as Mutex;
    const store = new JsonIdentitySessionStore(fileStore, mutex);
    const session = IdentitySession.create(
      'sess-1',
      'alice',
      IpAddress.create('10.0.0.10'),
      new Date('2026-05-02T10:00:00.000Z'),
      new Date('2026-05-02T10:30:00.000Z'),
      ['admins'],
      '192.168.20.254',
      'raptorgate',
      'uid=alice,ou=users,dc=raptorgate,dc=local',
      '00:11:22:33:44:55',
    );

    await store.upsert(session);

    expect(fileStore.writeJsonAtomic).toHaveBeenCalledWith(
      expect.stringContaining('identity_sessions.json'),
      {
        items: [
          {
            id: 'sess-1',
            identityUserId: 'uid=alice,ou=users,dc=raptorgate,dc=local',
            username: 'alice',
            sourceIp: '10.0.0.10',
            createdAt: '2026-05-02T10:00:00.000Z',
            expiresAt: '2026-05-02T10:30:00.000Z',
            groups: ['admins'],
            nasIp: '192.168.20.254',
            calledStationId: 'raptorgate',
            macAddress: '00:11:22:33:44:55',
          },
        ],
      },
    );
  });

  it('loads persisted sessions lazily', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({
        items: [
          {
            id: 'sess-1',
            identityUserId: 'user-1',
            username: 'alice',
            sourceIp: '10.0.0.10',
            createdAt: '2026-05-02T10:00:00.000Z',
            expiresAt: '2026-05-02T10:30:00.000Z',
            groups: ['admins'],
            nasIp: '192.168.20.254',
            calledStationId: 'raptorgate',
            macAddress: '00:11:22:33:44:55',
          },
        ],
      })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<unknown>) => fn()),
    } as unknown as Mutex;
    const store = new JsonIdentitySessionStore(fileStore, mutex);

    const found = await store.findBySourceIp('10.0.0.10');

    expect(found?.getId()).toBe('sess-1');
    expect(found?.getIdentityUserId()).toBe('user-1');
    expect(found?.getMacAddress()).toBe('00:11:22:33:44:55');
  });

  it('persists deletion when session is removed by source IP', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({
        items: [
          {
            id: 'sess-1',
            identityUserId: 'user-1',
            username: 'alice',
            sourceIp: '10.0.0.10',
            createdAt: '2026-05-02T10:00:00.000Z',
            expiresAt: '2026-05-02T10:30:00.000Z',
            groups: ['admins'],
            nasIp: '192.168.20.254',
            calledStationId: 'raptorgate',
            macAddress: '00:11:22:33:44:55',
          },
        ],
      })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<unknown>) => fn()),
    } as unknown as Mutex;
    const store = new JsonIdentitySessionStore(fileStore, mutex);

    const removed = await store.removeBySourceIp('10.0.0.10');

    expect(removed?.getId()).toBe('sess-1');
    expect(fileStore.writeJsonAtomic).toHaveBeenCalledWith(
      expect.stringContaining('identity_sessions.json'),
      { items: [] },
    );
  });

  it('returns only expired sessions', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({
        items: [
          {
            id: 'sess-expired',
            identityUserId: 'user-1',
            username: 'alice',
            sourceIp: '10.0.0.10',
            createdAt: '2026-05-02T09:00:00.000Z',
            expiresAt: '2026-05-02T10:00:00.000Z',
            groups: ['admins'],
            nasIp: '192.168.20.254',
            calledStationId: 'raptorgate',
            macAddress: '00:11:22:33:44:55',
          },
          {
            id: 'sess-active',
            identityUserId: 'user-2',
            username: 'bob',
            sourceIp: '10.0.0.11',
            createdAt: '2026-05-02T09:00:00.000Z',
            expiresAt: '2026-05-02T10:30:00.000Z',
            groups: ['users'],
            nasIp: '192.168.20.254',
            calledStationId: 'raptorgate',
            macAddress: '00:11:22:33:44:56',
          },
        ],
      })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<unknown>) => fn()),
    } as unknown as Mutex;
    const store = new JsonIdentitySessionStore(fileStore, mutex);

    const expired = await store.peekExpired(
      new Date('2026-05-02T10:00:00.000Z'),
    );

    expect(expired.map((session) => session.getId())).toEqual(['sess-expired']);
  });
});
