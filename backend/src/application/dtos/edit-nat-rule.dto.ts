import type { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';
import type { CreateNatRuleActionDto } from './create-nat-rule.dto.js';

export class EditNatRuleDto {
  id: string;
  isActive?: boolean;
  priority?: number;
  protocol?: NatProtocol;
  inInterface?: string | null;
  outInterface?: string | null;
  inZone?: string | null;
  outZone?: string | null;
  matchSrcPortMin?: number | null;
  matchSrcPortMax?: number | null;
  matchDstPortMin?: number | null;
  matchDstPortMax?: number | null;
  action?: CreateNatRuleActionDto;
}
