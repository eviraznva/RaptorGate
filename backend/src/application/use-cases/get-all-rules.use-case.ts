import { RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/rules-repository';
import type { IRulesRepository } from 'src/domain/repositories/rules-repository';
import { GetAllRulesDto } from '../dtos/get-all-rules.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class GetAllRulesUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
  ) {}

  async execute(): Promise<GetAllRulesDto> {
    const rules = await this.rulesRepository.findAll();

    return { rules };
  }
}
