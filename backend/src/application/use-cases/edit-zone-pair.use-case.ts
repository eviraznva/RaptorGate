import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import type { IZonePairRepository } from 'src/domain/repositories/zone-pair.repository';
import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import type { IZoneRepository } from 'src/domain/repositories/zone.repository';
import { EditZonePairDto } from '../dtos/edit-zone-pair.dto';
import { Injectable, Inject } from '@nestjs/common';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import { AtLeastOneFieldRequiredException } from 'src/domain/exceptions/at-least-one-field-required.exception';

@Injectable()
export class EditZonePairUseCase {
  constructor(
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
  ) {}

  async execute(dto: EditZonePairDto): Promise<void> {
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
  }
}
