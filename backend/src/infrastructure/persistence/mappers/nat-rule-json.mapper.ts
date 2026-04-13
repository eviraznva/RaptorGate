import { NatRule } from "../../../domain/entities/nat-rule.entity.js";
import { IpAddress } from "../../../domain/value-objects/ip-address.vo.js";
import { NatType } from "../../../domain/value-objects/nat-type.vo.js";
import { Port } from "../../../domain/value-objects/port.vo.js";
import { Priority } from "../../../domain/value-objects/priority.vo.js";
import { NatRuleRecord } from "../schemas/nat-rules.schema.js";

export class NatRuleJsonMapper {
  constructor() {}

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
