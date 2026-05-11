import { ZoneItemResponseDto } from './zone-item-response.dto';
import { ApiProperty } from '@nestjs/swagger';

export class EditZoneResponseDto {
  @ApiProperty({
    type: () => ZoneItemResponseDto,
    example: {
      id: 'c2bd07b0-ac5e-44a5-a2f0-af19bb72fde4',
      name: 'Bedroom',
      description: 'The bedroom of the house',
      isActive: true,
      createdAt: '2026-03-19T18:36:47.226Z',
      createdBy: '5ad2d67d-e9d9-4bfe-8708-d0c5b3138d92',
    },
  })
  zone: ZoneItemResponseDto;
}
