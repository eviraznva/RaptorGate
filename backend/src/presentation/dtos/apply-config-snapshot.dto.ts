import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';

export class ApplyConfigSnapshotDto {
  @ApiProperty({
    example: 'manual_import',
    enum: ['manual_import', 'rollback_point', 'auto_save'],
  })
  @IsString()
  @IsNotEmpty()
  @IsIn(['manual_import', 'rollback_point', 'auto_save'])
  snapshotType: string;

  @ApiProperty({ example: true })
  @IsBoolean()
  isActive: boolean;

  @ApiProperty({
    example: 'Imported configuration from admin panel',
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsString()
  @MaxLength(512)
  changeSummary: string | null;
}
