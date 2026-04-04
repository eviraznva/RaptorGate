import { NatRuleItemResponseDto } from '../dtos/nat-rule-item-response.dto';
import { NatRule } from '../../domain/entities/nat-rule.entity.js';

export class NatRuleResponseMapper {
  constructor() {}

  static toDto(natRule: NatRule): NatRuleItemResponseDto {
    return {
      id: natRule.getId(),
      type: natRule.getType().getValue(),
      isActive: natRule.getIsActive(),
      sourceIp: natRule.getSourceIp()?.getValue || null,
      destinationIp: natRule.getDestinationIp()?.getValue || null,
      sourcePort: natRule.getSourcePort()?.getValue || null,
      destinationPort: natRule.getDestinationPort()?.getValue || null,
      translatedIp: natRule.getTranslatedIp()?.getValue || null,
      translatedPort: natRule.getTranslatedPort()?.getValue || null,
      priority: natRule.getPriority().getValue(),
      createdAt: natRule.getCreatedAt().toISOString(),
      updatedAt: natRule.getUpdatedAt().toISOString(),
    };
  }
}
