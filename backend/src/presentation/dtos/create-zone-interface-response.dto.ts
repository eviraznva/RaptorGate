import { ApiProperty } from '@nestjs/swagger';
import { ZoneInterfaceItemResponseDto } from './zone-interface-item-response.dto.js';

export class CreateZoneInterfaceResponseDto {
  @ApiProperty({ type: () => ZoneInterfaceItemResponseDto })
  zoneInterface: ZoneInterfaceItemResponseDto;
}
