import { jest } from '@jest/globals';
import { SecretRecord } from '../../../domain/entities/secret-record.entity.js';
import { Mutex } from '../json/file-mutex.js';
import { FileStore } from '../json/file-store.js';
import { JsonSecretStoreRepository } from './json-secret-store.repository.js';

describe('JsonSecretStoreRepository', () => {
  const record = SecretRecord.create(
    'secret://identity/radius/default',
    'ciphertext',
    'iv',
    'auth-tag',
    new Date('2026-04-30T10:00:00.000Z'),
    new Date('2026-04-30T10:01:00.000Z'),
    'user-1',
  );

  it('saves encrypted secret records without plaintext fields', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({ items: [] })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<void>) => fn()),
    } as unknown as Mutex;
    const repository = new JsonSecretStoreRepository(fileStore, mutex);

    await repository.save(record);

    expect(fileStore.writeJsonAtomic).toHaveBeenCalledWith(
      expect.stringContaining('secrets.json'),
      {
        items: [
          {
            ref: 'secret://identity/radius/default',
            ciphertext: 'ciphertext',
            iv: 'iv',
            authTag: 'auth-tag',
            createdAt: '2026-04-30T10:00:00.000Z',
            updatedAt: '2026-04-30T10:01:00.000Z',
            updatedBy: 'user-1',
          },
        ],
      },
    );
    expect(JSON.stringify((fileStore.writeJsonAtomic as any).mock.calls[0][1])).not.toContain('radiussecret');
  });

  it('finds records by managed secret reference', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async () => ({
        items: [
          {
            ref: 'secret://identity/radius/default',
            ciphertext: 'ciphertext',
            iv: 'iv',
            authTag: 'auth-tag',
            createdAt: '2026-04-30T10:00:00.000Z',
            updatedAt: '2026-04-30T10:01:00.000Z',
            updatedBy: 'user-1',
          },
        ],
      })),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<void>) => fn()),
    } as unknown as Mutex;
    const repository = new JsonSecretStoreRepository(fileStore, mutex);

    const found = await repository.findByRef('secret://identity/radius/default');

    expect(found?.getRef()).toBe('secret://identity/radius/default');
    expect(found?.getCiphertext()).toBe('ciphertext');
  });
});
