import { IsOptional, IsString } from 'class-validator';
import type { ZonePairPolicy } from '../../domain/entities/zone-pair.entity.js';
import { PaginationQueryDto } from './pagination-query.dto';

export class GetZonePairsQueryDto extends PaginationQueryDto {
  @IsString()
  @IsOptional()
  defaultPolicy?: ZonePairPolicy;
}
