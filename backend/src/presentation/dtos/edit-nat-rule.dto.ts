import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsIn,
  IsInt,
  IsIP,
  IsOptional,
  Max,
  Min,
} from 'class-validator';

export class EditNatRuleDto {
  @ApiProperty({
    example: 'DNAT',
    enum: ['SNAT', 'DNAT', 'PAT'],
    required: false,
  })
  @IsOptional()
  @IsIn(['SNAT', 'DNAT', 'PAT'])
  type?: string;

  @ApiProperty({
    example: true,
    required: false,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @ApiProperty({
    example: '192.168.1.10',
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsIP()
  srcIp?: string | null;

  @ApiProperty({
    example: '10.0.0.5',
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsIP()
  dstIp?: string | null;

  @ApiProperty({
    example: 443,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(65535)
  srcPort?: number | null;

  @ApiProperty({
    example: 8080,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(65535)
  dstPort?: number | null;

  @ApiProperty({
    example: '172.16.0.20',
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsIP()
  translatedIp?: string | null;

  @ApiProperty({
    example: 8443,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(65535)
  translatedPort?: number | null;

  @ApiProperty({
    example: 10,
    required: false,
    minimum: 1,
    maximum: 100,
  })
  @IsInt()
  @Min(1)
  @Max(100)
  @IsOptional()
  priority?: number;
}
