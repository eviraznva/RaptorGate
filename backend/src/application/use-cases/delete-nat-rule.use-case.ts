import { Inject, Injectable } from "@nestjs/common";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import type { INatRulesRepository } from "../../domain/repositories/nat-rules.repository.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../../domain/repositories/nat-rules.repository.js";

@Injectable()
export class DeleteNatRuleUseCase {
  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(id: string): Promise<void> {
    const existingRule = await this.natRulesRepository.findById(id);
    if (!existingRule) throw new EntityNotFoundException("Nat rule", id);

    await this.natRulesRepository.delete(id);
  }
}
