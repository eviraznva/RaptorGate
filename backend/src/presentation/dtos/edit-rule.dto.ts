import {
  IsBoolean,
  IsInt,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
  MinLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class EditRuleDto {
  @ApiProperty({
    example: 'Allow HTTPS',
    minLength: 1,
    maxLength: 128,
  })
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  @IsOptional()
  name: string;

  @ApiProperty({
    example: 'Allow outgoing HTTPS traffic to external APIs',
    required: false,
    nullable: true,
  })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({
    example: '12345678-90ab-cdef-1234-567890abcdef',
    format: 'uuid',
  })
  @IsUUID()
  @IsOptional()
  zonePairId: string;

  @ApiProperty({
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  isActive: boolean;

  @ApiProperty({
    example: 'allow tcp any any eq 443',
    minLength: 1,
  })
  @IsString()
  @MinLength(1)
  @IsOptional()
  content: string;

  @ApiProperty({
    example: 10,
    minimum: 1,
    maximum: 100,
  })
  @IsInt()
  @Min(1)
  @Max(100)
  @IsOptional()
  priority: number;
}
