import { FirewallRule } from 'src/domain/entities/firewall-rule.entity';

export class GetAllRulesDto {
  rules: FirewallRule[];
}
