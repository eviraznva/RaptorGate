import { ApiProperty } from '@nestjs/swagger';
import type { ZoneInterfaceStatus } from '../../domain/entities/zone-interface.entity.js';

export class ZoneInterfaceItemResponseDto {
  @ApiProperty({ example: '123e4567-e89b-12d3-a456-426614174000' })
  id: string;

  @ApiProperty({ example: 'c2bd07b0-ac5e-44a5-a2f0-af19bb72fde4' })
  zoneId: string;

  @ApiProperty({ example: 'eth0' })
  interfaceName: string;

  @ApiProperty({ example: 20, nullable: true })
  vlanId: number | null;

  @ApiProperty({
    example: 'active',
    enum: ['unspecified', 'active', 'inactive', 'missing', 'unknown'],
  })
  status: ZoneInterfaceStatus;

  @ApiProperty({ type: [String], example: ['192.168.50.10/24'] })
  addresses: string[];

  @ApiProperty({ example: '2024-06-01T12:00:00Z' })
  createdAt: Date;
}
