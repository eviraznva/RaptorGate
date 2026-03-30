import type { ZonePairPolicy } from '../../domain/entities/zone-pair.entity.js';
import { IsNotEmpty, IsString, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateZonePairDto {
  @ApiProperty({
    example: 'c2bd07b0-ac5e-44a5-a2f0-af19bb72fde4',
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID('4')
  srcZoneId: string;

  @ApiProperty({
    example: 'a0db06f9-5063-4035-aadd-845248db19e4',
  })
  @IsNotEmpty()
  @IsString()
  @IsUUID('4')
  dstZoneId: string;

  @ApiProperty({
    example: 'ALLOW',
  })
  @IsNotEmpty()
  @IsString()
  defaultPolicy: ZonePairPolicy;
}
