import { NatRule } from '../../domain/entities/nat-rule.entity.js';

export class GetAllNatRulesResponseDto {
  natRules: NatRule[];
}
