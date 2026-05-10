import { NatRule, type NatRuleAction } from 'src/domain/entities/nat-rule.entity';
import {
  NatRuleItemResponseDto,
  type NatRuleActionResponseDto,
} from '../dtos/nat-rule-item-response.dto';

export class NatRuleResponseMapper {
  static toDto(natRule: NatRule): NatRuleItemResponseDto {
    return {
      id: natRule.getId(),
      isActive: natRule.getIsActive(),
      priority: natRule.getPriority().getValue(),
      protocol: natRule.getProtocol(),
      inInterface: natRule.getInInterface(),
      outInterface: natRule.getOutInterface(),
      inZone: natRule.getInZone(),
      outZone: natRule.getOutZone(),
      matchSrcPortMin: natRule.getMatchSrcPortMin()?.getValue ?? null,
      matchSrcPortMax: natRule.getMatchSrcPortMax()?.getValue ?? null,
      matchDstPortMin: natRule.getMatchDstPortMin()?.getValue ?? null,
      matchDstPortMax: natRule.getMatchDstPortMax()?.getValue ?? null,
      action: this.toActionDto(natRule.getAction()),
      createdAt: natRule.getCreatedAt().toISOString(),
      updatedAt: natRule.getUpdatedAt().toISOString(),
    };
  }

  private static toActionDto(action: NatRuleAction): NatRuleActionResponseDto {
    switch (action.$case) {
      case 'snat':
        return {
          $case: 'snat',
          snat: {
            srcCidr: action.snat.srcCidr,
            translatedIp: action.snat.translatedIp,
            srcPortMin: action.snat.srcPortMin?.getValue,
            srcPortMax: action.snat.srcPortMax?.getValue,
          },
        };
      case 'dnat':
        return {
          $case: 'dnat',
          dnat: {
            dstCidr: action.dnat.dstCidr,
            translatedIp: action.dnat.translatedIp,
            translatedPort: action.dnat.translatedPort?.getValue,
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
            srcCidr: action.masquerade.srcCidr,
            srcPortMin: action.masquerade.srcPortMin?.getValue,
            srcPortMax: action.masquerade.srcPortMax?.getValue,
          },
        };
    }
  }
}
