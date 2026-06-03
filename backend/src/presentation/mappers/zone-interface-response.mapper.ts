import { ZoneInterface } from '../../domain/entities/zone-interface.entity.js';
import { ZoneInterfaceItemResponseDto } from '../dtos/zone-interface-item-response.dto.js';

export class ZoneInterfaceResponseMapper {
  static toDto(
    zoneInterface: ZoneInterface,
    parentNameById?: Map<string, string>,
  ): ZoneInterfaceItemResponseDto {
    const parentInterfaceId = zoneInterface.getParentInterfaceId();
    const parentInterfaceName =
      parentInterfaceId != null
        ? (parentNameById?.get(parentInterfaceId) ?? null)
        : null;

    const vlanId = zoneInterface.getVlanId();
    const interfaceName =
      vlanId != null && parentInterfaceName
        ? `${parentInterfaceName}.${vlanId}`
        : zoneInterface.getInterfaceName();

    return {
      id: zoneInterface.getId(),
      zoneId: zoneInterface.getZoneId(),
      interfaceName,
      vlanId,
      status: zoneInterface.getStatus(),
      addresses: zoneInterface.getAddresses(),
      sniffed: zoneInterface.getSniffed(),
      createdAt: zoneInterface.getCreatedAt(),
      parentInterfaceId,
      parentInterfaceName,
    };
  }
}
