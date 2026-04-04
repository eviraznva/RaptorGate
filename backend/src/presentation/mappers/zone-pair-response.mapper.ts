import { ZonePairItemResponseDto } from '../dtos/zone-pair-item-response.dto';
import { ZonePair } from '../../domain/entities/zone-pair.entity.js';

export class ZonePairResponseMapper {
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
