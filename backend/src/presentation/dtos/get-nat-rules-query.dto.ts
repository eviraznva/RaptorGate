import { Transform } from 'class-transformer';
import { IsBoolean, IsEnum, IsIn, IsOptional } from 'class-validator';
import { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';
import { PaginationQueryDto } from './pagination-query.dto';

const toNatProtocol = (value: unknown): unknown => {
  if (typeof value === 'string') {
    return NatProtocol[value as keyof typeof NatProtocol];
  }

  return value;
};

export class GetNatRulesQueryDto extends PaginationQueryDto {
  @IsIn(['snat', 'dnat', 'pat', 'masquerade'])
  @IsOptional()
  actionKind?: 'snat' | 'dnat' | 'pat' | 'masquerade';

  @Transform(({ value }) => toNatProtocol(value))
  @IsEnum(NatProtocol)
  @IsOptional()
  protocol?: NatProtocol;

  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  @IsOptional()
  isActive?: boolean;
}
