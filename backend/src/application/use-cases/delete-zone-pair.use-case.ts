import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../../domain/repositories/zone-pair.repository.js';
import type { IZonePairRepository } from '../../domain/repositories/zone-pair.repository.js';
import { DeleteZonePairDto } from '../dtos/delete-zone-pair.dto.js';
import { Inject, Injectable } from '@nestjs/common';

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
