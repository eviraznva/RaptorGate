import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import {
  IsBoolean,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsObject,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';
import type { CreateNatRuleActionDto } from '../../application/dtos/create-nat-rule.dto.js';

const toNatProtocol = (value: unknown): unknown => {
  if (typeof value === 'string') {
    return NatProtocol[value as keyof typeof NatProtocol];
  }

  return value;
};

export class CreateNatRuleDto {
  @ApiProperty({ example: true })
  @IsBoolean()
  isActive: boolean;

  @ApiProperty({ example: 10, minimum: 1, maximum: 100 })
  @IsInt()
  @Min(1)
  @Max(100)
  priority: number;

  @ApiProperty({
    example: 'NAT_PROTOCOL_ALL',
    enum: ['NAT_PROTOCOL_ALL', 'NAT_PROTOCOL_TCP', 'NAT_PROTOCOL_UDP', 'NAT_PROTOCOL_ICMP'],
  })
  @Transform(({ value }) => toNatProtocol(value))
  @IsEnum(NatProtocol)
  protocol: NatProtocol;

  @ApiPropertyOptional({ example: 'lan0', nullable: true })
  @IsString()
  @IsOptional()
  inInterface?: string | null;

  @ApiPropertyOptional({ example: 'wan0', nullable: true })
  @IsString()
  @IsOptional()
  outInterface?: string | null;

  @ApiPropertyOptional({ example: 'lan', nullable: true })
  @IsString()
  @IsOptional()
  inZone?: string | null;

  @ApiPropertyOptional({ example: 'wan', nullable: true })
  @IsString()
  @IsOptional()
  outZone?: string | null;

  @ApiPropertyOptional({ example: 1024, nullable: true, minimum: 1, maximum: 65535 })
  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  matchSrcPortMin?: number | null;

  @ApiPropertyOptional({ example: 65535, nullable: true, minimum: 1, maximum: 65535 })
  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  matchSrcPortMax?: number | null;

  @ApiPropertyOptional({ example: 443, nullable: true, minimum: 1, maximum: 65535 })
  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  matchDstPortMin?: number | null;

  @ApiPropertyOptional({ example: 443, nullable: true, minimum: 1, maximum: 65535 })
  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  matchDstPortMax?: number | null;

  @ApiProperty({
    example: {
      $case: 'dnat',
      dnat: { dstCidr: '203.0.113.10/32', translatedIp: '10.0.0.10', translatedPort: 80 },
    },
  })
  @IsObject()
  @IsNotEmpty()
  action: CreateNatRuleActionDto;
}
