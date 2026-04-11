import { Inject, Injectable } from '@nestjs/common';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import type { IZonePairRepository } from '../../domain/repositories/zone-pair.repository.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../../domain/repositories/zone-pair.repository.js';
import type { DeleteZonePairDto } from '../dtos/delete-zone-pair.dto.js';

@Injectable()
export class DeleteZonePairUseCase {
  constructor(
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
  ) {}

  async execute(dto: DeleteZonePairDto): Promise<void> {
    const isExisting = await this.zonePairRepository.findById(dto.id);
    if (!isExisting) throw new EntityNotFoundException('Zone pair', dto.id);

    await this.zonePairRepository.findById(dto.id);
  }
}
