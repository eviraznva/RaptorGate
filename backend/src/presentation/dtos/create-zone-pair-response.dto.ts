import { ApiProperty } from '@nestjs/swagger';

export class CreateZonePairResponseDto {
  @ApiProperty({ example: '123e4567-e89b-12d3-a456-426614174000' })
  id: string;

  @ApiProperty({ example: 'c2bd07b0-ac5e-44a5-a2f0-af19bb72fde4' })
  srcZoneId: string;

  @ApiProperty({ example: 'a0db06f9-5063-4035-aadd-845248db19e4' })
  dstZoneId: string;

  @ApiProperty({ example: 'ALLOW', enum: ['ALLOW', 'DROP'] })
  defaultPolicy: string;

  @ApiProperty({ example: '2024-06-01T12:00:00Z' })
  createdAt: Date;

  @ApiProperty({ example: '345e4567-e89b-12d3-a456-426614174000' })
  createdBy: string;
}
