import {
  IsBoolean,
  IsIn,
  IsInt,
  IsIP,
  IsOptional,
  Max,
  Min,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class EditNatRuleDto {
  @ApiProperty({
    example: 'DNAT',
    enum: ['SNAT', 'DNAT', 'PAT'],
    required: false,
  })
  @IsIn(['SNAT', 'DNAT', 'PAT'])
  @IsOptional()
  type?: string;

  @ApiProperty({
    example: true,
    required: false,
  })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;

  @ApiProperty({
    example: '192.168.1.10',
    required: false,
    nullable: true,
  })
  @IsIP()
  @IsOptional()
  sourceIp?: string | null;

  @ApiProperty({
    example: '10.0.0.5',
    required: false,
    nullable: true,
  })
  @IsIP()
  @IsOptional()
  destinationIp?: string | null;

  @ApiProperty({
    example: 443,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  @IsInt()
  @Max(65535)
  @Min(1)
  @IsOptional()
  sourcePort?: number | null;

  @ApiProperty({
    example: 8080,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
  destinationPort?: number | null;

  @ApiProperty({
    example: '172.16.0.20',
    required: false,
    nullable: true,
  })
  @IsIP()
  @IsOptional()
  translatedIp?: string | null;

  @ApiProperty({
    example: 8443,
    required: false,
    nullable: true,
    minimum: 1,
    maximum: 65535,
  })
  @IsInt()
  @Min(1)
  @Max(65535)
  @IsOptional()
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
