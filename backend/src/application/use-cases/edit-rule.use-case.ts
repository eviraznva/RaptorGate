import { AtLeastOneFieldRequiredException } from '../../domain/exceptions/at-least-one-field-required.exception.js';
import { RAPTOR_LANG_VALIDATION_SERVICE_TOKEN } from '../ports/raptor-lang-validation-service.interface.js';
import { EntityAlreadyExistsException } from '../../domain/exceptions/entity-already-exists-exception.js';
import { type IRaptorLangValidationService } from '../ports/raptor-lang-validation-service.interface.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { RULES_REPOSITORY_TOKEN } from '../../domain/repositories/rules-repository.js';
import { EditRuleResponseDto } from '../dtos/edit-rule-response.dto.js';
import type { IRulesRepository } from '../../domain/repositories/rules-repository.js';
import { Priority } from '../../domain/value-objects/priority.vo.js';
import { EditRuleDto } from '../dtos/edit-rule.dto.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class EditRuleUseCase {
  constructor(
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
    @Inject(RAPTOR_LANG_VALIDATION_SERVICE_TOKEN)
    private readonly raptorLangValidationService: IRaptorLangValidationService,
  ) {}

  async execute(dto: EditRuleDto): Promise<EditRuleResponseDto> {
    const rule = await this.rulesRepository.findById(dto.id);
    if (!rule) throw new EntityNotFoundException('Nat rule', dto.id);

    if (
      dto.name === undefined &&
      dto.description === undefined &&
      dto.isActive === undefined &&
      dto.content === undefined &&
      dto.priority === undefined &&
      dto.zonePairId === undefined
    )
      throw new AtLeastOneFieldRequiredException();

    if (dto.name !== undefined) {
      const ruleByName = await this.rulesRepository.finfByName(dto.name);
      if (ruleByName && ruleByName.getId() !== dto.id)
        throw new EntityAlreadyExistsException('Nat rule', 'name', dto.name);

      rule.setName(dto.name);
    }
    if (dto.description !== undefined) rule.setDescription(dto.description);
    if (dto.isActive !== undefined) rule.setIsActive(dto.isActive);
    if (dto.content !== undefined) {
      await this.raptorLangValidationService.validateRaptorLang(dto.content);
      rule.setContent(dto.content);
    }
    if (dto.priority !== undefined)
      rule.setPriority(Priority.create(dto.priority));
    if (dto.zonePairId !== undefined) rule.setZonePairId(dto.zonePairId);

    rule.setUpdatedAt(new Date());

    await this.rulesRepository.save(rule);

    return {
      id: rule.getId(),
      name: rule.getName(),
      description: rule.getDescription(),
      zonePairId: rule.getZonePairId(),
      isActive: rule.getIsActive(),
      content: rule.getContent(),
      priority: rule.getPriority().getValue(),
      createdAt: rule.getCreatedAt(),
      updatedAt: rule.getUpdatedAt(),
      createdBy: rule.getCreatedBy(),
    };
  }
}
