import { Inject, Injectable } from '@nestjs/common';
import {
  ZONE_REPOSITORY_TOKEN,
  type IZoneRepository,
} from 'src/domain/repositories/zone.repository';

@Injectable()
export class DeleteZoneUseCase {
  constructor(
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
  ) {}

  async execute(id: string): Promise<void> {
    const isExisting = await this.zoneRepository.findById(id);
    if (!isExisting) throw new Error(`Zone with id ${id} not found`);

    await this.zoneRepository.delete(id);
  }
}
