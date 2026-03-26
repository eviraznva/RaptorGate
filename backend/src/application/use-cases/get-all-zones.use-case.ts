import { ZONE_REPOSITORY_TOKEN } from '../../domain/repositories/zone.repository.js';
import type { IZoneRepository } from '../../domain/repositories/zone.repository.js';
import { GetAllZonesDto } from '../dtos/get-all-zones.dto.js';
import { Inject } from '@nestjs/common';

export class GetAllZonesUseCase {
  constructor(
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
  ) {}

  async execute(): Promise<GetAllZonesDto> {
    const zones = await this.zoneRepository.findAll();
    return { zones };
  }
}
