import { Inject, Injectable } from '@nestjs/common';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import {
  type IZonePairRepository,
  ZONE_PAIR_REPOSITORY_TOKEN,
} from 'src/domain/repositories/zone-pair.repository';
import { GetAllZonePairsDto } from '../dtos/get-all-zone-pairs.dto';
import { GetZonePairsDto } from '../dtos/get-zone-pairs.dto';

@Injectable()
export class GetAllZonePairsUseCase {
  constructor(
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
  ) {}

  async execute(dto: GetZonePairsDto): Promise<GetAllZonePairsDto> {
    const zonePairs = await this.zonePairRepository.findAll();
    if (!zonePairs) throw new EntityNotFoundException('zone pairs', 'all');
    let result = zonePairs;

    if (dto.defaultPolicy !== undefined)
      result = result.filter(
        (zonePair) => zonePair.getDefaultPolicy() === dto.defaultPolicy,
      );

    if (dto.page !== undefined && dto.limit !== undefined)
      result = result.slice((dto.page - 1) * dto.limit, dto.page * dto.limit);

    return { zonePairs: result };
  }
}
