import { NatRule, type NatRuleAction } from '../../../domain/entities/nat-rule.entity.js';
import { NatConfigIsInvalidException } from '../../../domain/exceptions/nat-config-is-invalid.exception.js';
import { Port } from '../../../domain/value-objects/port.vo.js';
import { Priority } from '../../../domain/value-objects/priority.vo.js';
import { NatProtocol } from '../../grpc/generated/common/common.js';
import {
  NatRuleRecord,
  ProtoNatRuleRecord,
} from '../schemas/nat-rules.schema.js';

export class NatRuleJsonMapper {
  static toDomain(record: NatRuleRecord): NatRule {
    if ('action' in record) {
      return this.protoRecordToDomain(record);
    }

    return this.legacyRecordToDomain(record);
  }

  static toRecord(natRule: NatRule, createdBy: string): ProtoNatRuleRecord {
    return {
      id: natRule.getId(),
      isActive: natRule.getIsActive(),
      priority: natRule.getPriority().getValue(),
      protocol: NatProtocol[natRule.getProtocol()] as ProtoNatRuleRecord['protocol'],
      inInterface: natRule.getInInterface(),
      outInterface: natRule.getOutInterface(),
      inZone: natRule.getInZone(),
      outZone: natRule.getOutZone(),
      matchSrcPortMin: natRule.getMatchSrcPortMin()?.getValue ?? null,
      matchSrcPortMax: natRule.getMatchSrcPortMax()?.getValue ?? null,
      matchDstPortMin: natRule.getMatchDstPortMin()?.getValue ?? null,
      matchDstPortMax: natRule.getMatchDstPortMax()?.getValue ?? null,
      action: this.toRecordAction(natRule.getAction()),
      createdAt: natRule.getCreatedAt().toISOString(),
      updatedAt: natRule.getUpdatedAt().toISOString(),
      createdBy,
    };
  }

  private static protoRecordToDomain(record: ProtoNatRuleRecord): NatRule {
    const base = {
      id: record.id,
      isActive: record.isActive,
      priority: Priority.create(record.priority),
      protocol: this.toNatProtocol(record.protocol),
      inInterface: record.inInterface ?? null,
      outInterface: record.outInterface ?? null,
      inZone: record.inZone ?? null,
      outZone: record.outZone ?? null,
      matchSrcPortMin: this.toPort(record.matchSrcPortMin),
      matchSrcPortMax: this.toPort(record.matchSrcPortMax),
      matchDstPortMin: this.toPort(record.matchDstPortMin),
      matchDstPortMax: this.toPort(record.matchDstPortMax),
      createdAt: new Date(record.createdAt),
      updatedAt: new Date(record.updatedAt),
    };

    if (!record.action) {
      throw new NatConfigIsInvalidException('unknown', 'action', 'action is required');
    }

    const normalizedAction = this.normalizeActionShape(record.action);

    if (!normalizedAction?.$case) {
      throw new NatConfigIsInvalidException('unknown', 'action', 'action is required');
    }

    switch (normalizedAction.$case) {
      case 'snat':
        return NatRule.createSnatRule({ ...base, snat: normalizedAction.snat });
      case 'dnat':
        return NatRule.createDnatRule({ ...base, dnat: normalizedAction.dnat });
      case 'pat':
        return NatRule.createPatRule({ ...base, pat: normalizedAction.pat });
      case 'masquerade':
        return NatRule.createMasqueradeRule({
          ...base,
          masquerade: normalizedAction.masquerade,
        });
      default:
        throw new NatConfigIsInvalidException(
          (normalizedAction as { $case: string }).$case,
          'action',
          'unsupported action case',
        );
    }
  }

  private static normalizeActionShape(action: any): any {
    if ('$case' in action) {
      return action;
    }

    const keys = Object.keys(action);
    if (keys.length !== 1) {
      return undefined;
    }

    const variant = keys[0];
    if (!['snat', 'dnat', 'pat', 'masquerade'].includes(variant)) {
      return undefined;
    }

    return {
      $case: variant,
      [variant]: action[variant],
    };
  }

  private static legacyRecordToDomain(
    record: Exclude<NatRuleRecord, ProtoNatRuleRecord>,
  ): NatRule {
    const base = {
      id: record.id,
      isActive: record.isActive,
      priority: Priority.create(record.priority),
      protocol: NatProtocol.NAT_PROTOCOL_ALL,
      inInterface: null,
      outInterface: null,
      inZone: null,
      outZone: null,
      matchSrcPortMin: this.toPort(record.srcPort),
      matchSrcPortMax: this.toPort(record.srcPort),
      matchDstPortMin: this.toPort(record.dstPort),
      matchDstPortMax: this.toPort(record.dstPort),
      createdAt: new Date(record.createdAt),
      updatedAt: new Date(record.updatedAt),
    };

    switch (record.type) {
      case 'SNAT':
        if (!record.srcIp || !record.translatedIp) {
          throw new NatConfigIsInvalidException('SNAT', 'srcIp/translatedIp');
        }
        return NatRule.createSnatRule({
          ...base,
          snat: {
            srcCidr: this.toHostCidr(record.srcIp),
            translatedIp: record.translatedIp,
            srcPortMin: record.srcPort,
            srcPortMax: record.srcPort,
          },
        });
      case 'DNAT':
        if (!record.dstIp || !record.translatedIp) {
          throw new NatConfigIsInvalidException('DNAT', 'dstIp/translatedIp');
        }
        if (record.translatedPort != null) {
          throw new NatConfigIsInvalidException(
            'DNAT',
            'translatedPort',
            'translatedPort is not supported by proto DNAT action',
          );
        }
        return NatRule.createDnatRule({
          ...base,
          dnat: {
            dstCidr: this.toHostCidr(record.dstIp),
            translatedIp: record.translatedIp,
          },
        });
      case 'PAT':
        if (
          !record.dstIp ||
          record.dstPort == null ||
          !record.translatedIp ||
          record.translatedPort == null
        ) {
          throw new NatConfigIsInvalidException('PAT', 'action');
        }
        return NatRule.createPatRule({
          ...base,
          pat: {
            dstIp: record.dstIp,
            dstPort: record.dstPort,
            translatedIp: record.translatedIp,
            translatedPort: record.translatedPort,
          },
        });
      default:
        throw new NatConfigIsInvalidException(record.type, 'type');
    }
  }

  private static toRecordAction(
    action: NatRuleAction | undefined,
  ): ProtoNatRuleRecord['action'] {
    if (!action?.$case) {
      throw new NatConfigIsInvalidException('unknown', 'action', 'action is required');
    }

    switch (action.$case) {
      case 'snat':
        return {
          $case: 'snat',
          snat: {
            srcCidr: action.snat.srcCidr,
            translatedIp: action.snat.translatedIp,
            srcPortMin: action.snat.srcPortMin?.getValue ?? null,
            srcPortMax: action.snat.srcPortMax?.getValue ?? null,
          },
        };
      case 'dnat':
        return {
          $case: 'dnat',
          dnat: {
            dstCidr: action.dnat.dstCidr,
            translatedIp: action.dnat.translatedIp,
            translatedPort: action.dnat.translatedPort?.getValue ?? null,
          },
        };
      case 'pat':
        return {
          $case: 'pat',
          pat: {
            dstIp: action.pat.dstIp,
            dstPort: action.pat.dstPort.getValue,
            translatedIp: action.pat.translatedIp,
            translatedPort: action.pat.translatedPort.getValue,
          },
        };
      case 'masquerade':
        return {
          $case: 'masquerade',
          masquerade: {
            srcCidr: action.masquerade.srcCidr ?? null,
            srcPortMin: action.masquerade.srcPortMin?.getValue ?? null,
            srcPortMax: action.masquerade.srcPortMax?.getValue ?? null,
          },
        };
      default:
        throw new NatConfigIsInvalidException(
          (action as { $case: string }).$case,
          'action',
          'unsupported action case',
        );
    }
  }

  private static toNatProtocol(protocol: ProtoNatRuleRecord['protocol']): NatProtocol {
    return NatProtocol[protocol];
  }

  private static toPort(value: number | null | undefined): Port | null {
    return value != null ? Port.create(value) : null;
  }

  private static toHostCidr(ip: string): string {
    return ip.includes(':') ? `${ip}/128` : `${ip}/32`;
  }
}
