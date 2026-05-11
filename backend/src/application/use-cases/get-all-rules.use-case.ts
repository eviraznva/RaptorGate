import { Inject, Injectable } from "@nestjs/common";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import type { IRulesRepository } from "../../domain/repositories/rules-repository.js";
import { RULES_REPOSITORY_TOKEN } from "../../domain/repositories/rules-repository.js";
import { GetAllRulesResponseDto } from "../dtos/get-all-rules-response.dto.js";
import { GetRulesDto } from "../dtos/get-rules.dto.js";

@Injectable()
export class GetAllRulesUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
  ) {}

  async execute(dto: GetRulesDto): Promise<GetAllRulesResponseDto> {
    const rules = await this.rulesRepository.findAll();
    if (!rules) throw new EntityNotFoundException("rules", "all");
    let result = rules;

    if (dto.isActive !== undefined)
      result = result.filter((rule) => rule.getIsActive() === dto.isActive);

    if (dto.page !== undefined && dto.limit !== undefined)
      result = result.slice((dto.page - 1) * dto.limit, dto.page * dto.limit);

    return { rules: result };
  }
}
