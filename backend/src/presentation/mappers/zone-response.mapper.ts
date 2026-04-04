import { ZoneItemResponseDto } from '../dtos/zone-item-response.dto';
import { Zone } from '../../domain/entities/zone.entity.js';

export class ZoneResponseMapper {
  static toDto(zone: Zone): ZoneItemResponseDto {
    return {
      id: zone.getId(),
      name: zone.getName(),
      description: zone.getDescription(),
      isActive: zone.getIsActive(),
      createdAt: zone.getCreatedAt(),
      createdBy: zone.getCreatedBy(),
    };
  }
}
