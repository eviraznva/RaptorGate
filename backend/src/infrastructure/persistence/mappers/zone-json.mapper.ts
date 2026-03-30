import { Zone } from '../../../domain/entities/zone.entity.js';
import { ZoneRecord } from '../schemas/zones.schema.js';
import { Logger } from '@nestjs/common';

export class ZoneJsonMapper {
  private static readonly logger = new Logger(ZoneJsonMapper.name);
  constructor() {}

  static toDomain(record: ZoneRecord): Zone {
    return Zone.create(
      record.id,
      record.name,
      record.description || null,
      record.isActive,
      new Date(record.createdAt),
      record.createdBy,
    );
  }

  static toRecord(zone: Zone, createdBy: string): ZoneRecord {
    return {
      id: zone.getId(),
      name: zone.getName(),
      description: zone.getDescription(),
      isActive: zone.getIsActive(),
      createdAt: zone.getCreatedAt().toISOString(),
      createdBy: createdBy,
    };
  }
}
