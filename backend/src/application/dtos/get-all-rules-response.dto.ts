import { FirewallRule } from '../../domain/entities/firewall-rule.entity.js';

export class GetAllRulesResponseDto {
  rules: FirewallRule[];
}
