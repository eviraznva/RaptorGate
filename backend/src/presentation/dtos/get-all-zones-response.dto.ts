import { ApiProperty } from '@nestjs/swagger';
import { CreateZoneResponseDto } from './create-zone-response.dto.js';

export class GetAllZonesResponseDto {
  @ApiProperty({ type: () => [CreateZoneResponseDto] })
  zones: CreateZoneResponseDto[];
}
