import { NAT_RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/nat-rules.repository';
import type { INatRulesRepository } from 'src/domain/repositories/nat-rules.repository';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class DeleteNatRuleUseCase {
  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(id: string): Promise<void> {
    const existingRule = await this.natRulesRepository.findById(id);
    if (!existingRule) throw new Error(`NAT rule with id ${id} not found`);

    await this.natRulesRepository.delete(id);
  }
}
