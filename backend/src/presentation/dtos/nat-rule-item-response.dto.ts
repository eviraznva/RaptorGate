import { ApiProperty } from '@nestjs/swagger';
import { IsOptional } from 'class-validator';

export class NatRuleItemResponseDto {
  @ApiProperty({
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  id: string;

  @ApiProperty({
    example: 'SNAT',
    enum: ['SNAT', 'DNAT', 'PAT'],
  })
  type: string;

  @ApiProperty({
    example: true,
  })
  isActive: boolean;

  @ApiProperty({
    example: '192.168.1.10',
    required: false,
    nullable: true,
  })
  sourceIp: string | null;

  @ApiProperty({
    example: '10.0.0.5',
    required: false,
    nullable: true,
  })
  destinationIp: string | null;

  @ApiProperty({
    example: 443,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  sourcePort: number | null;

  @ApiProperty({
    example: 8080,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  destinationPort: number | null;

  @ApiProperty({
    example: '172.16.0.20',
    required: false,
    nullable: true,
  })
  translatedIp: string | null;

  @ApiProperty({
    example: 8443,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  @IsOptional()
  translatedPort: number | null;

  @ApiProperty({
    example: 10,
    minimum: 1,
    maximum: 100,
  })
  priority: number;

  @ApiProperty({
    example: '2024-06-01T12:00:00Z',
  })
  createdAt: string;

  @ApiProperty({
    example: '2024-06-01T12:00:00Z',
  })
  updatedAt: string;
}
