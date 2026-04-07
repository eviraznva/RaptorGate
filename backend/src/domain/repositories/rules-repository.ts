import { FirewallRule } from "../entities/firewall-rule.entity.js";

export interface IRulesRepository {
	save(rule: FirewallRule): Promise<void>;
	findById(id: string): Promise<FirewallRule | null>;
	findActive(): Promise<FirewallRule[]>;
	findAll(): Promise<FirewallRule[]>;
	finfByName(name: string): Promise<FirewallRule | null>;
	overwriteAll(rules: FirewallRule[]): Promise<void>;
	delete(id: string): Promise<void>;
}

export const RULES_REPOSITORY_TOKEN = Symbol("RULES_REPOSITORY_TOKEN");
