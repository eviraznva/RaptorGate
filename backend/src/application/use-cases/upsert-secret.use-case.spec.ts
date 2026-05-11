import { jest } from '@jest/globals';
import { SecretRecord } from '../../domain/entities/secret-record.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import type { ISecretStoreRepository } from '../../domain/repositories/secret-store.repository.js';
import type { ISecretCryptoService } from '../ports/secret-crypto.service.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { UpsertSecretUseCase } from './upsert-secret.use-case.js';

describe('UpsertSecretUseCase', () => {
  it('stores encrypted secret data and returns metadata only', async () => {
    const repository = {
      findByRef: jest.fn(async () => null),
      save: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<ISecretStoreRepository>;
    const useCase = new UpsertSecretUseCase(
      repository,
      {
        encrypt: jest.fn(() => ({
          ciphertext: 'ciphertext',
          iv: 'iv',
          authTag: 'auth-tag',
        })),
      } as unknown as ISecretCryptoService,
      {
        decodeAccessToken: jest.fn(() => ({
          sub: 'user-1',
          username: 'admin',
        })),
      } as unknown as ITokenService,
    );

    const result = await useCase.execute({
      scope: 'identity',
      type: 'radius',
      name: 'default',
      value: 'radiussecret',
      accessToken: 'token',
    });

    expect(repository.save).toHaveBeenCalledTimes(1);
    const saved = repository.save.mock.calls[0][0];
    expect(saved.getRef()).toBe('secret://identity/radius/default');
    expect(saved.getCiphertext()).toBe('ciphertext');
    expect(JSON.stringify(result)).not.toContain('radiussecret');
    expect(JSON.stringify(result)).not.toContain('ciphertext');
    expect(result.ref).toBe('secret://identity/radius/default');
    expect(result.updatedBy).toBe('user-1');
  });

  it('preserves createdAt when replacing an existing secret', async () => {
    const existing = SecretRecord.create(
      'secret://identity/radius/default',
      'old',
      'old-iv',
      'old-tag',
      new Date('2026-04-30T10:00:00.000Z'),
      new Date('2026-04-30T10:01:00.000Z'),
      'user-1',
    );
    const repository = {
      findByRef: jest.fn(async () => existing),
      save: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<ISecretStoreRepository>;
    const useCase = new UpsertSecretUseCase(
      repository,
      {
        encrypt: jest.fn(() => ({
          ciphertext: 'new',
          iv: 'new-iv',
          authTag: 'new-tag',
        })),
      } as unknown as ISecretCryptoService,
      {
        decodeAccessToken: jest.fn(() => ({
          sub: 'user-2',
          username: 'admin',
        })),
      } as unknown as ITokenService,
    );

    await useCase.execute({
      scope: 'identity',
      type: 'radius',
      name: 'default',
      value: 'newsecret',
      accessToken: 'token',
    });

    expect(repository.save.mock.calls[0][0].getCreatedAt()).toEqual(
      new Date('2026-04-30T10:00:00.000Z'),
    );
  });

  it('rejects invalid access tokens', async () => {
    const useCase = new UpsertSecretUseCase(
      { findByRef: jest.fn(), save: jest.fn() } as unknown as ISecretStoreRepository,
      { encrypt: jest.fn() } as unknown as ISecretCryptoService,
      { decodeAccessToken: jest.fn(() => null) } as unknown as ITokenService,
    );

    await expect(
      useCase.execute({
        scope: 'identity',
        type: 'radius',
        name: 'default',
        value: 'radiussecret',
        accessToken: 'token',
      }),
    ).rejects.toThrow(AccessTokenIsInvalidException);
  });
});
