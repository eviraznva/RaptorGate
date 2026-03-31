import { ZONE_PAIR_REPOSITORY_TOKEN } from '../../domain/repositories/zone-pair.repository.js';
import type { IZonePairRepository } from '../../domain/repositories/zone-pair.repository.js';
import { GetAllZonePairsDto } from '../dtos/get-all-zone-pairs.dto.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class GetAllZonePairsUseCase {
  constructor(
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
  ) {}

  async execute(): Promise<GetAllZonePairsDto> {
    const zonePairs = await this.zonePairRepository.findAll();

    return { zonePairs };
  }
}
