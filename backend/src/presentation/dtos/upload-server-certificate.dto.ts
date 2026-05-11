import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsInt,
  IsIP,
  IsNotEmpty,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';

export class UploadServerCertificateDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  certificatePem: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  privateKeyPem: string;

  @ApiProperty()
  @IsIP()
  bindAddress: string;

  @ApiPropertyOptional({ default: 443 })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(65535)
  bindPort?: number;

  @ApiPropertyOptional({ default: false })
  @IsOptional()
  @IsBoolean()
  inspectionBypass?: boolean;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
