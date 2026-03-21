import { NAT_RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/nat-rules.repository';
import type { INatRulesRepository } from 'src/domain/repositories/nat-rules.repository';
import { EditNatRuleDto } from '../dtos/edit-nat-rule.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class EditNatRuleUseCase {
  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(dto: EditNatRuleDto): Promise<void> {
    const natRule = await this.natRulesRepository.findById(dto.id);
    if (!natRule) throw new Error(`NAT rule with id ${dto.id} not found`);

    this.validateRequiredFields(dto);

    if (dto.type != null) natRule.setType(dto.type);
    if (dto.isActive != null) natRule.setIsActive(dto.isActive);
    if (dto.priority != null) natRule.setPriority(dto.priority);
    if (dto.sourceIp != null) natRule.setSourceIp(dto.sourceIp);
    if (dto.destinationIp != null) natRule.setDestinationIp(dto.destinationIp);
    if (dto.sourcePort != null) natRule.setSourcePort(dto.sourcePort);
    if (dto.destinationPort != null)
      natRule.setDestinationPort(dto.destinationPort);
    if (dto.translatedIp != null) natRule.setTranslatedIp(dto.translatedIp);
    if (dto.translatedPort != null)
      natRule.setTranslatedPort(dto.translatedPort);

    natRule.setUpdatedAt(new Date());
  }

  private validateRequiredFields(dto: EditNatRuleDto): void {
    if (dto.type === 'SNAT') {
      if (dto.sourceIp === null || dto.sourceIp === undefined) {
        throw new Error('Source IP is required for SNAT rule');
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new Error('Translated IP is required for SNAT rule');
      }

      if (dto.destinationIp !== null && dto.destinationIp !== undefined) {
        throw new Error('Destination IP is not allowed for SNAT rule');
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new Error('Source port is not allowed for SNAT rule');
      }

      if (dto.destinationPort !== null && dto.destinationPort !== undefined) {
        throw new Error('Destination port is not allowed for SNAT rule');
      }

      if (dto.translatedPort !== null && dto.translatedPort !== undefined) {
        throw new Error('Translated port is not allowed for SNAT rule');
      }
    }

    if (dto.type === 'DNAT') {
      if (dto.destinationIp === null || dto.destinationIp === undefined) {
        throw new Error('Destination IP is required for DNAT rule');
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new Error('Translated IP is required for DNAT rule');
      }

      if (dto.sourceIp !== null && dto.sourceIp !== undefined) {
        throw new Error('Source IP is not allowed for DNAT rule');
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new Error('Source port is not allowed for DNAT rule');
      }

      if (dto.destinationPort !== null && dto.destinationPort !== undefined) {
        throw new Error('Destination port is not allowed for DNAT rule');
      }

      if (dto.translatedPort !== null && dto.translatedPort !== undefined) {
        throw new Error('Translated port is not allowed for DNAT rule');
      }
    }

    if (dto.type === 'PAT') {
      if (dto.destinationIp === null || dto.destinationIp === undefined) {
        throw new Error('Destination IP is required for PAT rule');
      }

      if (dto.destinationPort === null || dto.destinationPort === undefined) {
        throw new Error('Destination port is required for PAT rule');
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new Error('Translated IP is required for PAT rule');
      }

      if (dto.translatedPort === null || dto.translatedPort === undefined) {
        throw new Error('Translated port is required for PAT rule');
      }

      if (dto.sourceIp !== null && dto.sourceIp !== undefined) {
        throw new Error('Source IP is not allowed for PAT rule');
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new Error('Source port is not allowed for PAT rule');
      }
    }
  }
}
