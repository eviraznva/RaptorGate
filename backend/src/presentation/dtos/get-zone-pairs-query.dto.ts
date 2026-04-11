import { IsOptional, IsString } from 'class-validator';
import type { ZonePairPolicy } from 'src/domain/entities/zone-pair.entity';
import { PaginationQueryDto } from './pagination-query.dto';

export class GetZonePairsQueryDto extends PaginationQueryDto {
  @IsString()
  @IsOptional()
  defaultPolicy?: ZonePairPolicy;
}
