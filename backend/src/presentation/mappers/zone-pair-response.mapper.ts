import { ZonePair } from "src/domain/entities/zone-pair.entity";
import { ZonePairItemResponseDto } from "../dtos/zone-pair-item-response.dto";

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
