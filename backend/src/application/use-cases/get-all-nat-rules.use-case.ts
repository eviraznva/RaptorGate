import { Inject, Injectable, Logger } from "@nestjs/common";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import type { INatRulesRepository } from "../../domain/repositories/nat-rules.repository.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../../domain/repositories/nat-rules.repository.js";
import type { GetAllNatRulesResponseDto } from "../dtos/get-all-nat-rules-response.dto.js";
import { GetNatRulesDto } from "../dtos/get-nat-rules.dto.js";

@Injectable()
export class GetAllNatRulesUseCase {
  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(dto: GetNatRulesDto): Promise<GetAllNatRulesResponseDto> {
    const natRules = await this.natRulesRepository.findAll();
    if (!natRules) throw new EntityNotFoundException("nat rules", "all");
    let result = natRules;

    if (dto.type !== undefined)
      result = result.filter((rule) => rule.getType().getValue() === dto.type);

    if (dto.isActive !== undefined)
      result = result.filter((rule) => rule.getIsActive() === dto.isActive);

    if (dto.page !== undefined && dto.limit !== undefined)
      result = result.slice((dto.page - 1) * dto.limit, dto.page * dto.limit);

    return { natRules: result };
  }
}
