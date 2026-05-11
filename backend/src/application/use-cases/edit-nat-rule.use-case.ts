import { Inject, Injectable, Logger } from "@nestjs/common";
import {
  NatRule,
  type NatRuleBaseProps,
} from "../../domain/entities/nat-rule.entity.js";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import { NatConfigIsInvalidException } from "../../domain/exceptions/nat-config-is-invalid.exception.js";
import type { INatRulesRepository } from "../../domain/repositories/nat-rules.repository.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../../domain/repositories/nat-rules.repository.js";
import { Port } from "../../domain/value-objects/port.vo.js";
import { Priority } from "../../domain/value-objects/priority.vo.js";
import type { CreateNatRuleActionDto } from "../dtos/create-nat-rule.dto.js";
import { EditNatRuleDto } from "../dtos/edit-nat-rule.dto.js";
import { EditNatRuleResponseDto } from "../dtos/edit-nat-rule-response.dto.js";

@Injectable()
export class EditNatRuleUseCase {
  private readonly logger = new Logger(EditNatRuleUseCase.name);

  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(dto: EditNatRuleDto): Promise<EditNatRuleResponseDto> {
    const existing = await this.natRulesRepository.findById(dto.id);
    if (!existing) throw new EntityNotFoundException("nat rule", dto.id);

    const natRule = this.rebuildNatRule(existing, dto);

    await this.natRulesRepository.save(natRule);

    this.logger.log({
      event: "nat_rule.update.succeeded",
      message: "NAT rule updated",
      natRuleId: natRule.getId(),
      actionKind: natRule.getActionKind(),
      isActive: natRule.getIsActive(),
      priority: natRule.getPriority().getValue(),
      changedFields: Object.entries(dto)
        .filter(([key, value]) => key !== "id" && value !== undefined)
        .map(([key]) => key),
    });

    return { natRule };
  }

  private rebuildNatRule(existing: NatRule, dto: EditNatRuleDto): NatRule {
    const base: NatRuleBaseProps = {
      id: existing.getId(),
      isActive: dto.isActive ?? existing.getIsActive(),
      priority:
        dto.priority !== undefined
          ? Priority.create(dto.priority)
          : existing.getPriority(),
      protocol: dto.protocol ?? existing.getProtocol(),
      inInterface:
        dto.inInterface !== undefined
          ? dto.inInterface
          : existing.getInInterface(),
      outInterface:
        dto.outInterface !== undefined
          ? dto.outInterface
          : existing.getOutInterface(),
      inZone: dto.inZone !== undefined ? dto.inZone : existing.getInZone(),
      outZone: dto.outZone !== undefined ? dto.outZone : existing.getOutZone(),
      matchSrcPortMin:
        dto.matchSrcPortMin !== undefined
          ? this.toPort(dto.matchSrcPortMin)
          : existing.getMatchSrcPortMin(),
      matchSrcPortMax:
        dto.matchSrcPortMax !== undefined
          ? this.toPort(dto.matchSrcPortMax)
          : existing.getMatchSrcPortMax(),
      matchDstPortMin:
        dto.matchDstPortMin !== undefined
          ? this.toPort(dto.matchDstPortMin)
          : existing.getMatchDstPortMin(),
      matchDstPortMax:
        dto.matchDstPortMax !== undefined
          ? this.toPort(dto.matchDstPortMax)
          : existing.getMatchDstPortMax(),
      createdAt: existing.getCreatedAt(),
      updatedAt: new Date(),
    };

    if (!dto.action) {
      return NatRule.createWithAction(base, existing.getAction());
    }

    return this.createRuleFromAction(base, dto.action);
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

  private toPort(value: number | null | undefined): Port | null {
    return value != null ? Port.create(value) : null;
  }
}
