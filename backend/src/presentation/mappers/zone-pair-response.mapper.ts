import { ZonePairItemResponseDto } from '../dtos/zone-pair-item-response.dto';
import { ZonePair } from 'src/domain/entities/zone-pair.entity';

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
