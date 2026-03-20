import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import type { IZoneRepository } from 'src/domain/repositories/zone.repository';
import { GetAllZonesDto } from '../dtos/get-all-zones.dto';
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
