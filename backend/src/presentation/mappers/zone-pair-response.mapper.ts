import { ZonePair } from '../../domain/entities/zone-pair.entity.js';
import { ZonePairItemResponseDto } from '../dtos/zone-pair-item-response.dto';

export class ZonePairResponseMapper {
  constructor() {}

  static toDto(zonePair: ZonePair): ZonePairItemResponseDto {
    return {
      id: zonePair.getId(),
      srcZoneId: zonePair.getSrcZoneId(),
      dstZoneId: zonePair.getDstZoneId(),
      defaultPolicy: zonePair.getDefaultPolicy(),
      createdAt: zonePair.getCreatedAt().toISOString(),
      createdBy: zonePair.getCreatedBy(),
    };
  }
}
