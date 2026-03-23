import { NatRule } from 'src/domain/entities/nat-rule.entity';

export class GetAllNatRulesResponseDto {
  natRules: NatRule[];
}
