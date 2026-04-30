import { ApiProperty } from '@nestjs/swagger';
import { ZoneInterfaceItemResponseDto } from './zone-interface-item-response.dto.js';

export class GetLiveZoneInterfacesResponseDto {
  @ApiProperty({ type: () => [ZoneInterfaceItemResponseDto] })
  zoneInterfaces: ZoneInterfaceItemResponseDto[];
}
