import { Inject, Injectable } from '@nestjs/common';
import { FirewallRule } from '../../domain/entities/firewall-rule.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { EntityAlreadyExistsException } from '../../domain/exceptions/entity-already-exists-exception.js';
import {
  type IRulesRepository,
  RULES_REPOSITORY_TOKEN,
} from '../../domain/repositories/rules-repository.js';
import { Priority } from '../../domain/value-objects/priority.vo.js';
import { CreateRuleDto } from '../dtos/create-rule.dto.js';
import { CreateRuleResponseDto } from '../dtos/create-rule-response.dto.js';
import type { IRaptorLangValidationService } from '../ports/raptor-lang-validation-service.interface.js';
import { RAPTOR_LANG_VALIDATION_SERVICE_TOKEN } from '../ports/raptor-lang-validation-service.interface.js';
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from '../ports/token-service.interface.js';

@Injectable()
export class CreateRuleUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(RAPTOR_LANG_VALIDATION_SERVICE_TOKEN)
    private readonly raptorLangValidationService: IRaptorLangValidationService,
  ) {}

  async execute(dto: CreateRuleDto): Promise<CreateRuleResponseDto> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const ruleByName = await this.rulesRepository.finfByName(dto.name);

    if (ruleByName)
      throw new EntityAlreadyExistsException('rule', 'name', dto.name);

    await this.raptorLangValidationService.validateRaptorLang(dto.content);

    const newRule = FirewallRule.create(
      crypto.randomUUID(),
      dto.name,
      dto.description || null,
      dto.zonePairId,
      dto.isActive,
      dto.content,
      Priority.create(dto.priority),
      new Date(),
      new Date(),
      claims.sub,
    );

    await this.rulesRepository.save(newRule);

    return { rule: newRule };
  }
}
