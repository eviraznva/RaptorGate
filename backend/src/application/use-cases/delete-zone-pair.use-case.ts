import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import type { IZonePairRepository } from 'src/domain/repositories/zone-pair.repository';
import { DeleteZonePairDto } from '../dtos/delete-zone-pair.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class DeleteZonePairUseCase {
  constructor(
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
  ) {}

  async execute(dto: DeleteZonePairDto): Promise<void> {
    await this.zonePairRepository.findById(dto.id);
  }
}
