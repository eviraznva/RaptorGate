import {
  ZONE_REPOSITORY_TOKEN,
  type IZoneRepository,
} from 'src/domain/repositories/zone.repository';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import type { IZonePairRepository } from 'src/domain/repositories/zone-pair.repository';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class DeleteZoneUseCase {
  constructor(
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
  ) {}

  async execute(id: string): Promise<void> {
    const isExisting = await this.zoneRepository.findById(id);
    if (!isExisting) throw new EntityNotFoundException('zone', id);

    const zonePairsByDst = await this.zonePairRepository.findByDstZoneId(id);
    const zonePairsBySrc = await this.zonePairRepository.findBySrcZoneId(id);

    if (zonePairsByDst.length > 0)
      await Promise.all(
        zonePairsByDst.map((z) => this.zonePairRepository.delete(z.getId())),
      );

    if (zonePairsBySrc.length > 0)
      await Promise.all(
        zonePairsBySrc.map((z) => this.zonePairRepository.delete(z.getId())),
      );

    await this.zoneRepository.delete(id);
  }
}
