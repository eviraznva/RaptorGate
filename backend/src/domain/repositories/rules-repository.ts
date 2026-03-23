import { FirewallRule } from '../entities/firewall-rule.entity';

export interface IRulesRepository {
  save(rule: FirewallRule): Promise<void>;
  findById(id: string): Promise<FirewallRule | null>;
  findActive(): Promise<FirewallRule[]>;
  findAll(): Promise<FirewallRule[]>;
  finfByName(name: string): Promise<FirewallRule | null>;
  delete(id: string): Promise<void>;
}

export const RULES_REPOSITORY_TOKEN = Symbol('RULES_REPOSITORY_TOKEN');
