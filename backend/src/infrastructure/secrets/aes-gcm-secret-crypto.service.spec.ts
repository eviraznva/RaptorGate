import { jest } from '@jest/globals';
import type { ConfigService } from '@nestjs/config';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type { Env } from '../../shared/config/env.validation.js';
import { AesGcmSecretCryptoService } from './aes-gcm-secret-crypto.service.js';

describe('AesGcmSecretCryptoService', () => {
  function serviceForKey(key: Buffer): AesGcmSecretCryptoService {
    const configService = {
      get: jest.fn((name: keyof Env) =>
        name === 'SECRET_STORE_KEY' ? key.toString('base64') : undefined,
      ),
    } as unknown as ConfigService<Env, true>;

    return new AesGcmSecretCryptoService(configService);
  }

  it('encrypts and decrypts a secret value', () => {
    const service = serviceForKey(Buffer.alloc(32, 7));

    const encrypted = service.encrypt(SecretValue.create('radiussecret'));

    expect(encrypted.ciphertext).not.toContain('radiussecret');
    expect(service.decrypt(encrypted).getValue()).toBe('radiussecret');
  });

  it('uses a new ciphertext for each encryption', () => {
    const service = serviceForKey(Buffer.alloc(32, 7));

    const first = service.encrypt(SecretValue.create('radiussecret'));
    const second = service.encrypt(SecretValue.create('radiussecret'));

    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(first.iv).not.toBe(second.iv);
  });

  it('rejects ciphertext encrypted with a different key', () => {
    const encrypted = serviceForKey(Buffer.alloc(32, 7)).encrypt(
      SecretValue.create('radiussecret'),
    );

    expect(() => serviceForKey(Buffer.alloc(32, 8)).decrypt(encrypted)).toThrow();
  });
});
