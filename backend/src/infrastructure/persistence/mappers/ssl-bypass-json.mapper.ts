import { SslBypassEntry } from '../../../domain/entities/ssl-bypass-entry.entity.js';
import { SslBypassRecord } from '../schemas/ssl-bypass-list.schema.js';

export class SslBypassJsonMapper {
  static toDomain(record: SslBypassRecord): SslBypassEntry {
    return SslBypassEntry.create(
      record.id,
      record.domain,
      record.reason,
      record.isActive,
      new Date(record.createdAt),
    );
  }

  static toRecord(
    entry: SslBypassEntry,
    createdBy: string,
  ): SslBypassRecord {
    return {
      id: entry.getId(),
      domain: entry.getDomain(),
      reason: entry.getReason(),
      isActive: entry.getIsActive(),
      createdAt: entry.getCreatedAt().toISOString(),
      createdBy,
    };
  }
}
