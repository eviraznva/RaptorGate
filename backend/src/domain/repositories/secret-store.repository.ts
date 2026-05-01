import { SecretRecord } from '../entities/secret-record.entity.js';

export interface ISecretStoreRepository {
  exists(ref: string): Promise<boolean>;
  findByRef(ref: string): Promise<SecretRecord | null>;
  save(record: SecretRecord): Promise<void>;
  delete(ref: string): Promise<void>;
}

export const SECRET_STORE_REPOSITORY_TOKEN = Symbol(
  'SECRET_STORE_REPOSITORY_TOKEN',
);
