import { RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/rules-repository';
import type { IRulesRepository } from 'src/domain/repositories/rules-repository';
import { FirewallRule } from 'src/domain/entities/firewall-rule.entity';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { Priority } from 'src/domain/value-objects/priority.vo';
import { CreateRuleDto } from '../dtos/create-rule.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class CreateRuleUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: CreateRuleDto): Promise<void> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new Error('Invalid access token');

    const ruleByName = await this.rulesRepository.finfByName(dto.name);

    if (ruleByName) throw new Error('Rule name already exists');

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
