import {
  TOKEN_SERVICE_TOKEN,
  type ITokenService,
} from '../ports/token-service.interface';
import {
  RULES_REPOSITORY_TOKEN,
  type IRulesRepository,
} from 'src/domain/repositories/rules-repository';
import { RAPTOR_LANG_VALIDATION_SERVICE_TOKEN } from '../ports/raptor-lang-validation-service.interface';
import { AccessTokenIsInvalidException } from 'src/domain/exceptions/acces-token-is-invalid.exception';
import { EntityAlreadyExistsException } from 'src/domain/exceptions/entity-already-exists-exception';
import type { IRaptorLangValidationService } from '../ports/raptor-lang-validation-service.interface';
import { FirewallRule } from 'src/domain/entities/firewall-rule.entity';
import { Priority } from 'src/domain/value-objects/priority.vo';
import { CreateRuleDto } from '../dtos/create-rule.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class CreateRuleUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(RAPTOR_LANG_VALIDATION_SERVICE_TOKEN)
    private readonly raptorLangValidationService: IRaptorLangValidationService,
  ) {}

  async execute(dto: CreateRuleDto): Promise<void> {
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
  }
}
