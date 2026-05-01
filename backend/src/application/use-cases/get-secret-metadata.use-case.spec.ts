import { jest } from '@jest/globals';
import { SecretRecord } from '../../domain/entities/secret-record.entity.js';
import { SecretNotFoundException } from '../../domain/exceptions/secret-not-found.exception.js';
import type { ISecretStoreRepository } from '../../domain/repositories/secret-store.repository.js';
import { GetSecretMetadataUseCase } from './get-secret-metadata.use-case.js';

describe('GetSecretMetadataUseCase', () => {
  it('returns secret metadata without encrypted or plaintext values', async () => {
    const useCase = new GetSecretMetadataUseCase({
      findByRef: jest.fn(async () =>
        SecretRecord.create(
          'secret://identity/radius/default',
          'ciphertext',
          'iv',
          'auth-tag',
          new Date('2026-04-30T10:00:00.000Z'),
          new Date('2026-04-30T10:01:00.000Z'),
          'user-1',
        ),
      ),
    } as unknown as ISecretStoreRepository);

    const result = await useCase.execute({
      scope: 'identity',
      type: 'radius',
      name: 'default',
    });

    expect(result).toEqual({
      ref: 'secret://identity/radius/default',
      createdAt: new Date('2026-04-30T10:00:00.000Z'),
      updatedAt: new Date('2026-04-30T10:01:00.000Z'),
      updatedBy: 'user-1',
    });
    expect(JSON.stringify(result)).not.toContain('ciphertext');
  });

  it('throws when secret metadata is missing', async () => {
    const useCase = new GetSecretMetadataUseCase({
      findByRef: jest.fn(async () => null),
    } as unknown as ISecretStoreRepository);

    await expect(
      useCase.execute({
        scope: 'identity',
        type: 'radius',
        name: 'missing',
      }),
    ).rejects.toThrow(SecretNotFoundException);
  });
});
