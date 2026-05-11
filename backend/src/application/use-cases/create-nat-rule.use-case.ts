import { Inject, Injectable, Logger } from "@nestjs/common";
import {
  NatRule,
  type NatRuleBaseProps,
} from "../../domain/entities/nat-rule.entity.js";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import { NatConfigIsInvalidException } from "../../domain/exceptions/nat-config-is-invalid.exception.js";
import type { INatRulesRepository } from "../../domain/repositories/nat-rules.repository.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../../domain/repositories/nat-rules.repository.js";
import { Port } from "../../domain/value-objects/port.vo.js";
import { Priority } from "../../domain/value-objects/priority.vo.js";
import {
  type CreateNatRuleActionDto,
  CreateNatRuleDto,
} from "../dtos/create-nat-rule.dto.js";
import { CreateNatRuleResponseDto } from "../dtos/create-nat-rule-response.dto.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";

@Injectable()
export class CreateNatRuleUseCase {
  private readonly logger = new Logger(CreateNatRuleUseCase.name);

  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: CreateNatRuleDto): Promise<CreateNatRuleResponseDto> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    this.validate(dto);

    const now = new Date();
    const base: NatRuleBaseProps = {
      id: crypto.randomUUID(),
      isActive: dto.isActive,
      priority: Priority.create(dto.priority),
      protocol: dto.protocol,
      inInterface: dto.inInterface ?? null,
      outInterface: dto.outInterface ?? null,
      inZone: dto.inZone ?? null,
      outZone: dto.outZone ?? null,
      matchSrcPortMin: this.toPort(dto.matchSrcPortMin),
      matchSrcPortMax: this.toPort(dto.matchSrcPortMax),
      matchDstPortMin: this.toPort(dto.matchDstPortMin),
      matchDstPortMax: this.toPort(dto.matchDstPortMax),
      createdAt: now,
      updatedAt: now,
    };

    const newNatRule = this.createRuleFromAction(base, dto.action);

    await this.natRulesRepository.save(newNatRule, claims.sub);

    this.logger.log({
      event: "nat_rule.create.succeeded",
      message: "NAT rule created",
      actorId: claims.sub,
      natRuleId: newNatRule.getId(),
      actionKind: newNatRule.getActionKind(),
      isActive: newNatRule.getIsActive(),
      priority: newNatRule.getPriority().getValue(),
    });

    return { natRule: newNatRule };
  }

  private createRuleFromAction(
    base: NatRuleBaseProps,
    action: CreateNatRuleActionDto,
  ): NatRule {
    switch (action.$case) {
      case "snat":
        return NatRule.createSnatRule({ ...base, snat: action.snat });
      case "dnat":
        return NatRule.createDnatRule({ ...base, dnat: action.dnat });
      case "pat":
        return NatRule.createPatRule({ ...base, pat: action.pat });
      case "masquerade":
        return NatRule.createMasqueradeRule({
          ...base,
          masquerade: action.masquerade,
        });
      default:
        throw new NatConfigIsInvalidException("unknown", "action");
    }
  }

  private validate(dto: CreateNatRuleDto): void {
    if (!dto.action) {
      throw new NatConfigIsInvalidException("unknown", "action");
    }

    this.validatePortRange(
      dto.matchSrcPortMin,
      dto.matchSrcPortMax,
      dto.action.$case,
      "matchSrcPort",
    );
    this.validatePortRange(
      dto.matchDstPortMin,
      dto.matchDstPortMax,
      dto.action.$case,
      "matchDstPort",
    );

    if (dto.action.$case === "masquerade" && !dto.outInterface) {
      throw new NatConfigIsInvalidException(
        "masquerade",
        "outInterface",
        "outInterface is required for masquerade NAT rule",
      );
    }
  }

  private validatePortRange(
    min: number | null | undefined,
    max: number | null | undefined,
    type: string,
    field: string,
  ): void {
    if (min != null && max != null && min > max) {
      throw new NatConfigIsInvalidException(
        type,
        field,
        `${field} min cannot be greater than max`,
      );
    }
  }

  private toPort(value: number | null | undefined): Port | null {
    return value != null ? Port.create(value) : null;
  }
}
