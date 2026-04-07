import { NatRule } from "../entities/nat-rule.entity.js";

export interface INatRulesRepository {
	save(natRule: NatRule, createdBy?: string): Promise<void>;
	findById(id: string): Promise<NatRule | null>;
	findAll(): Promise<NatRule[]>;
	findActive(): Promise<NatRule[]>;
	findByType(type: string): Promise<NatRule[]>;
	findBySourceIp(sourceIp: string): Promise<NatRule[]>;
	findByDestinationIp(destinationIp: string): Promise<NatRule[]>;
	findBySourcePort(sourcePort: number): Promise<NatRule[]>;
	findByDestinationPort(destinationPort: number): Promise<NatRule[]>;
	overwriteAll(natRules: NatRule[]): Promise<void>;
	delete(id: string): Promise<void>;
}

export const NAT_RULES_REPOSITORY_TOKEN = Symbol("NAT_RULES_REPOSITORY_TOKEN");
