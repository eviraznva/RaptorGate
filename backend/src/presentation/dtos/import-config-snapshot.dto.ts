import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsDateString,
  IsNotEmpty,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  MinLength,
} from 'class-validator';

export class ImportConfigSnapshotDto {
  @ApiProperty()
  @IsUUID()
  id: string;

  @ApiProperty()
  @IsNumber()
  versionNumber: number;

  @ApiProperty()
  @IsString()
  @MinLength(1)
  @MaxLength(32)
  snapshotType: string;

  @ApiProperty()
  @IsString()
  @MinLength(1)
  @MaxLength(128)
  checksum: string;

  @ApiProperty()
  @IsBoolean()
  isActive: boolean;

  @ApiProperty()
  @IsObject()
  @IsNotEmpty()
  payloadJson: Record<string, unknown>;

  @ApiProperty({ required: false, nullable: true })
  @IsOptional()
  @IsString()
  changeSummary: string | null;

  @ApiProperty()
  @IsDateString()
  createdAt: string;

  @ApiProperty()
  @IsUUID()
  createdBy: string;
}
