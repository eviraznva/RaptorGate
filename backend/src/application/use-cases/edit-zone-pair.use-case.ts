import { AtLeastOneFieldRequiredException } from '../../domain/exceptions/at-least-one-field-required.exception.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../../domain/repositories/zone-pair.repository.js';
import type { IZonePairRepository } from '../../domain/repositories/zone-pair.repository.js';
import { EditZonePairResponseDto } from '../dtos/edit-zone-pair-response.dto.js';
import { ZONE_REPOSITORY_TOKEN } from '../../domain/repositories/zone.repository.js';
import type { IZoneRepository } from '../../domain/repositories/zone.repository.js';
import { EditZonePairDto } from '../dtos/edit-zone-pair.dto.js';
import { Injectable, Inject } from '@nestjs/common';

@Injectable()
export class EditZonePairUseCase {
  constructor(
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
  ) {}

  async execute(dto: EditZonePairDto): Promise<EditZonePairResponseDto> {
    const zonePairExists = await this.zonePairRepository.findById(dto.id);
    if (!zonePairExists) throw new EntityNotFoundException('Zone pair', dto.id);

    const isAllUndefined =
      dto.dstZoneId === undefined &&
      dto.srcZoneId === undefined &&
      dto.defaultPolicy === undefined;

    if (isAllUndefined) throw new AtLeastOneFieldRequiredException();

    if (dto.srcZoneId !== undefined) {
      const srcZoneExists = await this.zoneRepository.findById(dto.srcZoneId);

      if (!srcZoneExists)
        throw new EntityNotFoundException('zone', dto.srcZoneId);

      zonePairExists.setSrcZoneId(dto.srcZoneId);
    }

    if (dto.dstZoneId !== undefined) {
      const dstZoneExists = await this.zoneRepository.findById(dto.dstZoneId);

      if (!dstZoneExists)
        throw new EntityNotFoundException('zone', dto.dstZoneId);

      zonePairExists.setDstZoneId(dto.dstZoneId);
    }
    if (dto.defaultPolicy !== undefined)
      zonePairExists.setDefaultPolicy(dto.defaultPolicy);

    await this.zonePairRepository.save(zonePairExists);

    return {
      id: zonePairExists.getId(),
      srcZoneId: zonePairExists.getSrcZoneId(),
      dstZoneId: zonePairExists.getDstZoneId(),
      defaultPolicy: zonePairExists.getDefaultPolicy(),
      createdAt: zonePairExists.getCreatedAt(),
      createdBy: zonePairExists.getCreatedBy(),
    };
  }
}
