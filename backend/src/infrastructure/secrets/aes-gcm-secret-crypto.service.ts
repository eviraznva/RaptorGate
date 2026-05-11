import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SecretIsInvalidException } from '../../domain/exceptions/secret-is-invalid.exception.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type { Env } from '../../shared/config/env.validation.js';
import type {
  ISecretCryptoService,
  SecretEncryptedValue,
} from '../../application/ports/secret-crypto.service.js';

@Injectable()
export class AesGcmSecretCryptoService implements ISecretCryptoService {
  private readonly key: Buffer;

  constructor(private readonly configService: ConfigService<Env, true>) {
    const key = this.configService.get('SECRET_STORE_KEY', { infer: true });
    this.key = Buffer.from(key, 'base64');

    if (this.key.length !== 32) {
      throw new SecretIsInvalidException(
        'SECRET_STORE_KEY must be a base64 encoded 32 byte key',
      );
    }
  }

  encrypt(value: SecretValue): SecretEncryptedValue {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(value.getValue(), 'utf8'),
      cipher.final(),
    ]);

    return {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
    };
  }

  decrypt(value: SecretEncryptedValue): SecretValue {
    try {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        this.key,
        Buffer.from(value.iv, 'base64'),
      );
      decipher.setAuthTag(Buffer.from(value.authTag, 'base64'));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(value.ciphertext, 'base64')),
        decipher.final(),
      ]);

      return SecretValue.create(plaintext.toString('utf8'));
    } catch {
      throw new SecretIsInvalidException('secret ciphertext could not be decrypted');
    }
  }
}
