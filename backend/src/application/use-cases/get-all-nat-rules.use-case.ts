import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { NAT_RULES_REPOSITORY_TOKEN } from '../../domain/repositories/nat-rules.repository.js';
import type { INatRulesRepository } from '../../domain/repositories/nat-rules.repository.js';
import { GetAllNatRulesDto } from '../dtos/get-all-nat-rules.dto.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class GetAllNatRulesUseCase {
  constructor(
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(): Promise<GetAllNatRulesDto> {
    const natRules = await this.natRulesRepository.findAll();
    if (!natRules) throw new EntityNotFoundException('nat rules', 'all');

    return { natRules };
  }
}
