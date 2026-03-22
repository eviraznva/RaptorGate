import { FirewallRule } from 'src/domain/entities/firewall-rule.entity';
import { Priority } from 'src/domain/value-objects/priority.vo';
import { RuleRecord } from '../schemas/rules.schema';

export class RuleJsonMapper {
  constructor() {}

  static toDomain(record: RuleRecord): FirewallRule {
    return FirewallRule.create(
      record.id,
      record.name,
      record.description || null,
      record.zonePairId,
      record.isActive,
      record.content,
      Priority.create(record.priority),
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.createdBy,
    );
  }

  static toRecord(rule: FirewallRule): RuleRecord {
    return {
      id: rule.getId(),
      name: rule.getName(),
      zonePairId: rule.getZonePairId(),
      isActive: rule.getIsActive(),
      content: rule.getContent(),
      priority: rule.getPriority().getValue(),
      createdBy: rule.getCreatedBy(),
      createdAt: rule.getCreatedAt().toISOString(),
      updatedAt: rule.getUpdatedAt().toISOString(),
      description: rule.getDescription(),
    };
  }
}
