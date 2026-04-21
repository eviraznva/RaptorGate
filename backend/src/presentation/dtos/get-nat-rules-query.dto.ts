import { Transform, Type } from 'class-transformer';
import { IsBoolean, IsIn, IsOptional } from 'class-validator';
import { PaginationQueryDto } from './pagination-query.dto';

export class GetNatRulesQueryDto extends PaginationQueryDto {
  @IsIn(['SNAT', 'DNAT', 'PAT'])
  @IsOptional()
  type?: string;

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  @IsOptional()
  isActive?: boolean;
}
