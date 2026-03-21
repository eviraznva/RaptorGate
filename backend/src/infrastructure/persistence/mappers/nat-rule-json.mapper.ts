import { NatRule } from 'src/domain/entities/nat-rule.entity';
import { IpAddress } from 'src/domain/value-objects/ip-address.vo';
import { NatType } from 'src/domain/value-objects/nat-type.vo';
import { Port } from 'src/domain/value-objects/port.vo';
import { Priority } from 'src/domain/value-objects/priority.vo';
import { NatRuleRecord } from '../schemas/nat-rules.schema';

export class NatRuleJsonMapper {
  static toDomain(record: NatRuleRecord): NatRule {
    return NatRule.create(
      record.id,
      NatType.create(record.type),
      record.isActive,
      record.srcIp ? IpAddress.create(record.srcIp) : null,
      record.dstIp ? IpAddress.create(record.dstIp) : null,
      record.srcPort !== null && record.srcPort !== undefined
        ? Port.create(record.srcPort)
        : null,
      record.dstPort !== null && record.dstPort !== undefined
        ? Port.create(record.dstPort)
        : null,
      record.translatedIp ? IpAddress.create(record.translatedIp) : null,
      record.translatedPort !== null && record.translatedPort !== undefined
        ? Port.create(record.translatedPort)
        : null,
      Priority.create(record.priority),
      new Date(record.createdAt),
      new Date(record.updatedAt),
    );
  }

  static toRecord(natRule: NatRule, createdBy: string): NatRuleRecord {
    return {
      id: natRule.getId(),
      type: natRule.getType().getValue(),
      isActive: natRule.getIsActive(),
      srcIp: natRule.getSourceIp()?.getValue ?? null,
      dstIp: natRule.getDestinationIp()?.getValue ?? null,
      srcPort: natRule.getSourcePort()?.getValue ?? null,
      dstPort: natRule.getDestinationPort()?.getValue ?? null,
      translatedIp: natRule.getTranslatedIp()?.getValue ?? null,
      translatedPort: natRule.getTranslatedPort()?.getValue ?? null,
      priority: natRule.getPriority().getValue(),
      createdAt: natRule.getCreatedAt().toISOString(),
      updatedAt: natRule.getUpdatedAt().toISOString(),
      createdBy,
    };
  }
}
