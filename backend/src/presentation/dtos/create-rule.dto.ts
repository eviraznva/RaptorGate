import {
  IsBoolean,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
  MinLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateRuleDto {
  @ApiProperty({
    example: 'Allow HTTPS',
    minLength: 1,
    maxLength: 128,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  name: string;

  @ApiProperty({
    example: 'Allow outgoing HTTPS traffic to external APIs',
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty({
    example: '12345678-90ab-cdef-1234-567890abcdef',
    format: 'uuid',
  })
  @IsNotEmpty()
  @IsUUID()
  zonePairId: string;

  @ApiProperty({
    example: true,
  })
  @IsBoolean()
  isActive: boolean;

  @ApiProperty({
    example: 'allow tcp any any eq 443',
    minLength: 1,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(1)
  content: string;

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
