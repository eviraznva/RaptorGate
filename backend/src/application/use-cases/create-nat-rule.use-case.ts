import { AccessTokenIsInvalidException } from 'src/domain/exceptions/acces-token-is-invalid.exception';
import { NatConfigIsInvalidException } from 'src/domain/exceptions/nat-config-is-invalid.exception';
import { NAT_RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/nat-rules.repository';
import type { INatRulesRepository } from 'src/domain/repositories/nat-rules.repository';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { Priority } from 'src/domain/value-objects/priority.vo';
import { NatType } from 'src/domain/value-objects/nat-type.vo';
import { CreateNatRuleDto } from '../dtos/create-nat-rule.dto';
import { NatRule } from 'src/domain/entities/nat-rule.entity';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class CreateNatRuleUseCase {
  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: CreateNatRuleDto): Promise<void> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    this.validateRequiredFields(dto);

    const newNatRule = NatRule.create(
      crypto.randomUUID(),
      NatType.create(dto.type),
      dto.isActive,
      null,
      null,
      null,
      null,
      null,
      null,
      Priority.create(dto.priority),
      new Date(),
      new Date(),
    );

    if (dto.sourceIp != null) newNatRule.setSourceIp(dto.sourceIp);
    if (dto.destinationIp != null)
      newNatRule.setDestinationIp(dto.destinationIp);
    if (dto.sourcePort != null) newNatRule.setSourcePort(dto.sourcePort);
    if (dto.destinationPort != null)
      newNatRule.setDestinationPort(dto.destinationPort);
    if (dto.translatedIp != null) newNatRule.setTranslatedIp(dto.translatedIp);
    if (dto.translatedPort != null)
      newNatRule.setTranslatedPort(dto.translatedPort);

    await this.natRulesRepository.save(newNatRule, claims.sub);
  }

  private validateRequiredFields(dto: CreateNatRuleDto): void {
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
