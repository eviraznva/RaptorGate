import type { NatRule, NatRuleAction } from '../entities/nat-rule.entity.js';
import type { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';

export interface INatRulesRepository {
  save(natRule: NatRule, createdBy?: string): Promise<void>;
  findById(id: string): Promise<NatRule | null>;
  findAll(): Promise<NatRule[]>;
  findActive(): Promise<NatRule[]>;
  findByActionKind(kind: NatRuleAction['$case']): Promise<NatRule[]>;
  findByProtocol(protocol: NatProtocol): Promise<NatRule[]>;
  overwriteAll(natRules: NatRule[]): Promise<void>;
  delete(id: string): Promise<void>;
}

export const NAT_RULES_REPOSITORY_TOKEN = Symbol('NAT_RULES_REPOSITORY_TOKEN');
