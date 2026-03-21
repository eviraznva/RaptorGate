import { NAT_RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/nat-rules.repository';
import type { INatRulesRepository } from 'src/domain/repositories/nat-rules.repository';
import { GetAllNatRulesDto } from '../dtos/get-all-nat-rules.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class GetAllNatRulesUseCase {
  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(): Promise<GetAllNatRulesDto> {
    const natRules = await this.natRulesRepository.findAll();
    if (!natRules) throw new Error('Failed to retrieve NAT rules');

    return { natRules };
  }
}
