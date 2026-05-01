import { jest } from '@jest/globals';
import type { ConfigService } from '@nestjs/config';
import { SecretRecord } from '../../domain/entities/secret-record.entity.js';
import { SecretNotFoundException } from '../../domain/exceptions/secret-not-found.exception.js';
import type { ISecretStoreRepository } from '../../domain/repositories/secret-store.repository.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type { Env } from '../../shared/config/env.validation.js';
import type { ISecretCryptoService } from '../ports/secret-crypto.service.js';
import { SecretResolverService } from './secret-resolver.service.js';

describe('SecretResolverService', () => {
  it('resolves environment references from ConfigService', async () => {
    const configService = {
      get: jest.fn((name: keyof Env) =>
        name === 'RADIUS_SECRET' ? 'radiussecret' : undefined,
      ),
    } as unknown as ConfigService<Env, true>;
    const resolver = new SecretResolverService(
      configService,
      { findByRef: jest.fn() } as unknown as ISecretStoreRepository,
      { decrypt: jest.fn() } as unknown as ISecretCryptoService,
    );

    await expect(resolver.resolve('env:RADIUS_SECRET')).resolves.toEqual(
      SecretValue.create('radiussecret'),
    );
  });

  it('resolves managed references from the encrypted secret store', async () => {
    const record = SecretRecord.create(
      'secret://identity/radius/default',
      'ciphertext',
      'iv',
      'auth-tag',
      new Date('2026-04-30T10:00:00.000Z'),
      new Date('2026-04-30T10:01:00.000Z'),
      'user-1',
    );
    const resolver = new SecretResolverService(
      { get: jest.fn() } as unknown as ConfigService<Env, true>,
      { findByRef: jest.fn(async () => record) } as unknown as ISecretStoreRepository,
      {
        decrypt: jest.fn(() => SecretValue.create('radiussecret')),
      } as unknown as ISecretCryptoService,
    );

    await expect(resolver.resolve('secret://identity/radius/default')).resolves.toEqual(
      SecretValue.create('radiussecret'),
    );
  });

  it('throws when a managed reference is missing', async () => {
    const resolver = new SecretResolverService(
      { get: jest.fn() } as unknown as ConfigService<Env, true>,
      { findByRef: jest.fn(async () => null) } as unknown as ISecretStoreRepository,
      { decrypt: jest.fn() } as unknown as ISecretCryptoService,
    );

    await expect(resolver.resolve('secret://identity/radius/default')).rejects.toThrow(
      SecretNotFoundException,
    );
  });
});
