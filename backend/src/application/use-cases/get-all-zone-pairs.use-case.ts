import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import type { IZonePairRepository } from 'src/domain/repositories/zone-pair.repository';
import { GetAllZonePairsDto } from '../dtos/get-all-zone-pairs.dto';
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
