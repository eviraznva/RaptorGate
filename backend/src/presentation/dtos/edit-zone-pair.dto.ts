import type { ZonePairPolicy } from 'src/domain/entities/zone-pair.entity';
import { ApiProperty } from '@nestjs/swagger';
import { IsOptional } from 'class-validator';

export class EditZonePairDto {
  @ApiProperty({
    example: '12345678-90ab-cdef-1234-567890abcdef',
  })
  @IsOptional()
  srcZoneId?: string;

  @ApiProperty({
    example: '12345678-90ab-cdef-1234-567890abcdef',
  })
  @IsOptional()
  dstZoneId?: string;

  @ApiProperty({
    example: 'ALLOW',
  })
  @IsOptional()
  defaultPolicy?: ZonePairPolicy;
}
