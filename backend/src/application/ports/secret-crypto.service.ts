import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';

export interface SecretEncryptedValue {
  ciphertext: string;
  iv: string;
  authTag: string;
}

export interface ISecretCryptoService {
  encrypt(value: SecretValue): SecretEncryptedValue;
  decrypt(value: SecretEncryptedValue): SecretValue;
}

export const SECRET_CRYPTO_SERVICE_TOKEN = Symbol('SECRET_CRYPTO_SERVICE_TOKEN');
