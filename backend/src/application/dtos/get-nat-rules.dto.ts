import type { NatRuleAction } from '../../domain/entities/nat-rule.entity.js';
import type { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';
import { PaginationDto } from './pagination.dto';

export class GetNatRulesDto extends PaginationDto {
  actionKind?: NatRuleAction['$case'];
  protocol?: NatProtocol;
  isActive?: boolean;
}
