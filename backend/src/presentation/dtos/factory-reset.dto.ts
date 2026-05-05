import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class FactoryResetDto {
  @ApiPropertyOptional({ example: 'operator requested reset' })
  @IsOptional()
  @IsString()
  reason?: string;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  clearPki?: boolean;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  clearServerKeys?: boolean;
}

export class FactoryResetResponseDto {
  @ApiProperty({ example: '123e4567-e89b-12d3-a456-426614174000' })
  correlationId: string;

  @ApiProperty({ example: true })
  accepted: boolean;

  @ApiProperty({ example: '' })
  message: string;

  @ApiProperty({ example: true })
  safeStateApplied: boolean;

  @ApiProperty({ example: 2 })
  removedServerKeys: number;

  @ApiProperty({ example: 4 })
  removedServerKeyFiles: number;

  @ApiProperty({ example: 6 })
  removedCaFiles: number;
}
