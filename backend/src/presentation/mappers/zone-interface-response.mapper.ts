import { ZoneInterface } from '../../domain/entities/zone-interface.entity.js';
import { ZoneInterfaceItemResponseDto } from '../dtos/zone-interface-item-response.dto.js';

export class ZoneInterfaceResponseMapper {
  static toDto(zoneInterface: ZoneInterface): ZoneInterfaceItemResponseDto {
    return {
      id: zoneInterface.getId(),
      zoneId: zoneInterface.getZoneId(),
      interfaceName: zoneInterface.getInterfaceName(),
      vlanId: zoneInterface.getVlanId(),
      status: zoneInterface.getStatus(),
      addresses: zoneInterface.getAddresses(),
      createdAt: zoneInterface.getCreatedAt(),
    };
  }
}
