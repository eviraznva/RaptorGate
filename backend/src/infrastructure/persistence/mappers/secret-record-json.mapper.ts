import { SecretRecord } from '../../../domain/entities/secret-record.entity.js';
import type { SecretRecordJson } from '../schemas/secrets.schema.js';

export class SecretRecordJsonMapper {
  static toDomain(record: SecretRecordJson): SecretRecord {
    return SecretRecord.create(
      record.ref,
      record.ciphertext,
      record.iv,
      record.authTag,
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.updatedBy,
    );
  }

  static toRecord(record: SecretRecord): SecretRecordJson {
    return {
      ref: record.getRef(),
      ciphertext: record.getCiphertext(),
      iv: record.getIv(),
      authTag: record.getAuthTag(),
      createdAt: record.getCreatedAt().toISOString(),
      updatedAt: record.getUpdatedAt().toISOString(),
      updatedBy: record.getUpdatedBy(),
    };
  }
}
