import { NatConfigIsInvalidException } from '../../domain/exceptions/nat-config-is-invalid.exception.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { NAT_RULES_REPOSITORY_TOKEN } from '../../domain/repositories/nat-rules.repository.js';
import type { INatRulesRepository } from '../../domain/repositories/nat-rules.repository.js';
import { EditNatRuleDto } from '../dtos/edit-nat-rule.dto.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class EditNatRuleUseCase {
  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(dto: EditNatRuleDto): Promise<void> {
    const natRule = await this.natRulesRepository.findById(dto.id);
    if (!natRule) throw new EntityNotFoundException('nat rule', dto.id);

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

    await this.natRulesRepository.save(natRule);
  }

  private validateRequiredFields(dto: EditNatRuleDto): void {
    if (dto.type === 'SNAT') {
      if (dto.sourceIp === null || dto.sourceIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'sourceIp',
          'Source IP is required for SNAT rule',
        );
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'translatedIp',
          'Translated IP is required for SNAT rule',
        );
      }

      if (dto.destinationIp !== null && dto.destinationIp !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'destinationIp',
          'Destination IP is not allowed for SNAT rule',
        );
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'sourcePort',
          'Source port is not allowed for SNAT rule',
        );
      }

      if (dto.destinationPort !== null && dto.destinationPort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'destinationPort',
          'Destination port is not allowed for SNAT rule',
        );
      }

      if (dto.translatedPort !== null && dto.translatedPort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'translatedPort',
          'Translated port is not allowed for SNAT rule',
        );
      }
    }

    if (dto.type === 'DNAT') {
      if (dto.destinationIp === null || dto.destinationIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'destinationIp',
          'Destination IP is required for DNAT rule',
        );
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'translatedIp',
          'Translated IP is required for DNAT rule',
        );
      }

      if (dto.sourceIp !== null && dto.sourceIp !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'sourceIp',
          'Source IP is not allowed for DNAT rule',
        );
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'sourcePort',
          'Source port is not allowed for DNAT rule',
        );
      }

      if (dto.destinationPort !== null && dto.destinationPort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'destinationPort',
          'Destination port is not allowed for DNAT rule',
        );
      }

      if (dto.translatedPort !== null && dto.translatedPort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'translatedPort',
          'Translated port is not allowed for DNAT rule',
        );
      }
    }

    if (dto.type === 'PAT') {
      if (dto.destinationIp === null || dto.destinationIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'destinationIp',
          'Destination IP is required for PAT rule',
        );
      }

      if (dto.destinationPort === null || dto.destinationPort === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'destinationPort',
          'Destination port is required for PAT rule',
        );
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'translatedIp',
          'Translated IP is required for PAT rule',
        );
      }

      if (dto.translatedPort === null || dto.translatedPort === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'translatedPort',
          'Translated port is required for PAT rule',
        );
      }

      if (dto.sourceIp !== null && dto.sourceIp !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'sourceIp',
          'Source IP is not allowed for PAT rule',
        );
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          'sourcePort',
          'Source port is not allowed for PAT rule',
        );
      }
    }
  }
}
