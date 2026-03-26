import { FirewallRule } from 'src/domain/entities/firewall-rule.entity';

export class GetAllRulesResponseDto {
  rules: FirewallRule[];
}
