import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { RULES_REPOSITORY_TOKEN } from '../../domain/repositories/rules-repository.js';
import type { IRulesRepository } from '../../domain/repositories/rules-repository.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class DeleteRuleUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
  ) {}

  async execute(id: string): Promise<void> {
    const rule = await this.rulesRepository.findById(id);
    if (!rule) throw new EntityNotFoundException('rule', id);

    await this.rulesRepository.delete(id);
  }
}
