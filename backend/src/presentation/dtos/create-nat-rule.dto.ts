import {
  IsBoolean,
  IsIn,
  IsInt,
  IsIP,
  IsNotEmpty,
  IsOptional,
  Max,
  Min,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateNatRuleDto {
  @ApiProperty({
    example: 'SNAT',
    enum: ['SNAT', 'DNAT', 'PAT'],
  })
  @IsNotEmpty()
  @IsIn(['SNAT', 'DNAT', 'PAT'])
  type: string;

  @ApiProperty({
    example: true,
  })
  @IsBoolean()
  isActive: boolean;

  @ApiProperty({
    example: '192.168.1.10',
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsIP()
  sourceIp: string | null;

  @ApiProperty({
    example: '10.0.0.5',
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsIP()
  destinationIp: string | null;

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
  sourcePort: number | null;

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
  destinationPort: number | null;

  @ApiProperty({
    example: '172.16.0.20',
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsIP()
  translatedIp: string | null;

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
  translatedPort: number | null;

  @ApiProperty({
    example: 10,
    minimum: 1,
    maximum: 100,
  })
  @IsInt()
  @Min(1)
  @Max(100)
  priority: number;
}
