import { RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/rules-repository';
import type { IRulesRepository } from 'src/domain/repositories/rules-repository';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class DeleteRuleUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
  ) {}

  async execute(id: string): Promise<void> {
    const rule = await this.rulesRepository.findById(id);
    if (!rule) throw new Error('Rule not found');

    await this.rulesRepository.delete(id);
  }
}
