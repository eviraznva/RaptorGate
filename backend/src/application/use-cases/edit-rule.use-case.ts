import { RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/rules-repository';
import type { IRulesRepository } from 'src/domain/repositories/rules-repository';
import { Priority } from 'src/domain/value-objects/priority.vo';
import { Inject, Injectable } from '@nestjs/common';
import { EditRuleDto } from '../dtos/edit-rule.dto';

@Injectable()
export class EditRuleUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
  ) {}

  async execute(dto: EditRuleDto): Promise<void> {
    const rule = await this.rulesRepository.findById(dto.id);
    if (!rule) throw new Error('Rule not found');

    if (
      dto.name === undefined &&
      dto.description === undefined &&
      dto.isActive === undefined &&
      dto.content === undefined &&
      dto.priority === undefined &&
      dto.zonePairId === undefined
    )
      throw new Error('At least one field must be provided for update');

    if (dto.name !== undefined) {
      const ruleByName = await this.rulesRepository.finfByName(dto.name);
      if (ruleByName && ruleByName.getId() !== dto.id)
        throw new Error('Rule name already exists');

      rule.setName(dto.name);
    }
    if (dto.description !== undefined) rule.setDescription(dto.description);
    if (dto.isActive !== undefined) rule.setIsActive(dto.isActive);
    if (dto.content !== undefined) rule.setContent(dto.content);
    if (dto.priority !== undefined)
      rule.setPriority(Priority.create(dto.priority));
    if (dto.zonePairId !== undefined) rule.setZonePairId(dto.zonePairId);

    rule.setUpdatedAt(new Date());

    await this.rulesRepository.save(rule);
  }
}
