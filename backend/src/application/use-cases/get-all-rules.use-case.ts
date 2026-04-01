import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { RULES_REPOSITORY_TOKEN } from '../../domain/repositories/rules-repository.js';
import type { IRulesRepository } from '../../domain/repositories/rules-repository.js';
import { GetAllRulesResponseDto } from '../dtos/get-all-rules-response.dto.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class GetAllRulesUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
  ) {}

  async execute(): Promise<GetAllRulesResponseDto> {
    const rules = await this.rulesRepository.findAll();
    if (!rules) throw new EntityNotFoundException('rules', 'all');

    return { rules };
  }
}
