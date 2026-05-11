import {
  ZONE_REPOSITORY_TOKEN,
  type IZoneRepository,
} from '../../domain/repositories/zone.repository.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../../domain/repositories/zone-pair.repository.js';
import type { IZonePairRepository } from '../../domain/repositories/zone-pair.repository.js';
import { Inject, Injectable, Logger } from '@nestjs/common';

@Injectable()
export class DeleteZoneUseCase {
  private readonly logger = new Logger(DeleteZoneUseCase.name);

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

    this.logger.log({
      event: 'zone.delete.succeeded',
      message: 'zone deleted',
      zoneId: isExisting.getId(),
      zoneName: isExisting.getName(),
      deletedZonePairs: zonePairsByDst.length + zonePairsBySrc.length,
    });
  }
}
