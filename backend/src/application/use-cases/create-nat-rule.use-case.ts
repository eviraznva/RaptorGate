import { Inject, Injectable, Logger } from "@nestjs/common";
import { NatRule } from "../../domain/entities/nat-rule.entity.js";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import { NatConfigIsInvalidException } from "../../domain/exceptions/nat-config-is-invalid.exception.js";
import type { INatRulesRepository } from "../../domain/repositories/nat-rules.repository.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../../domain/repositories/nat-rules.repository.js";
import { NatType } from "../../domain/value-objects/nat-type.vo.js";
import { Priority } from "../../domain/value-objects/priority.vo.js";
import { CreateNatRuleDto } from "../dtos/create-nat-rule.dto.js";
import { CreateNatRuleResponseDto } from "../dtos/create-nat-rule-response.dto.js";
import {
  FIREWALL_NAT_CONFIG_QUERY_SERVICE_TOKEN,
  type IFirewallNatConfigQueryService,
} from "../ports/firewall-nat-config-query-service.interface.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";

@Injectable()
export class CreateNatRuleUseCase {
  private readonly logger = new Logger(CreateNatRuleUseCase.name);

  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(FIREWALL_NAT_CONFIG_QUERY_SERVICE_TOKEN)
    private readonly firewallNatConfigQueryService: IFirewallNatConfigQueryService,
  ) {}

  async execute(dto: CreateNatRuleDto): Promise<CreateNatRuleResponseDto> {
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

    this.logger.log({
      event: "nat_rule.create.succeeded",
      message: "NAT rule created",
      actorId: claims.sub,
      natRuleId: newNatRule.getId(),
      type: newNatRule.getType().getValue(),
      isActive: newNatRule.getIsActive(),
      priority: newNatRule.getPriority().getValue(),
    });

    const allNatRules = await this.natRulesRepository.findAll();

    await this.firewallNatConfigQueryService.swapNatConfig(allNatRules);

    return { natRule: newNatRule };
  }

  private validateRequiredFields(dto: CreateNatRuleDto): void {
    if (dto.type === "SNAT") {
      if (dto.sourceIp === null || dto.sourceIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "sourceIp",
          "Source IP is required for SNAT rule",
        );
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "translatedIp",
          "Translated IP is required for SNAT rule",
        );
      }

      if (dto.destinationIp !== null && dto.destinationIp !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "destinationIp",
          "Destination IP is not allowed for SNAT rule",
        );
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "sourcePort",
          "Source port is not allowed for SNAT rule",
        );
      }

      if (dto.destinationPort !== null && dto.destinationPort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "destinationPort",
          "Destination port is not allowed for SNAT rule",
        );
      }

      if (dto.translatedPort !== null && dto.translatedPort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "translatedPort",
          "Translated port is not allowed for SNAT rule",
        );
      }
    }

    if (dto.type === "DNAT") {
      if (dto.destinationIp === null || dto.destinationIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "destinationIp",
          "Destination IP is required for DNAT rule",
        );
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "translatedIp",
          "Translated IP is required for DNAT rule",
        );
      }

      if (dto.sourceIp !== null && dto.sourceIp !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "sourceIp",
          "Source IP is not allowed for DNAT rule",
        );
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "sourcePort",
          "Source port is not allowed for DNAT rule",
        );
      }

      if (dto.destinationPort !== null && dto.destinationPort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "destinationPort",
          "Destination port is not allowed for DNAT rule",
        );
      }

      if (dto.translatedPort !== null && dto.translatedPort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "translatedPort",
          "Translated port is not allowed for DNAT rule",
        );
      }
    }

    if (dto.type === "PAT") {
      if (dto.destinationIp === null || dto.destinationIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "destinationIp",
          "Destination IP is required for PAT rule",
        );
      }

      if (dto.destinationPort === null || dto.destinationPort === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "destinationPort",
          "Destination port is required for PAT rule",
        );
      }

      if (dto.translatedIp === null || dto.translatedIp === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "translatedIp",
          "Translated IP is required for PAT rule",
        );
      }

      if (dto.translatedPort === null || dto.translatedPort === undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "translatedPort",
          "Translated port is required for PAT rule",
        );
      }

      if (dto.sourceIp !== null && dto.sourceIp !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "sourceIp",
          "Source IP is not allowed for PAT rule",
        );
      }

      if (dto.sourcePort !== null && dto.sourcePort !== undefined) {
        throw new NatConfigIsInvalidException(
          dto.type,
          "sourcePort",
          "Source port is not allowed for PAT rule",
        );
      }
    }
  }
}
