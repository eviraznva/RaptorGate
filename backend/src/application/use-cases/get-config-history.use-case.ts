import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { GetConfigHistoryDto } from '../dtos/get-config-history.dto.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class GetConfigHistoryUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
  ) {}

  async execute(): Promise<GetConfigHistoryDto> {
    const configHistory =
      await this.configSnapshotRepository.findAllSnapshots();

    return { configHistory };
  }
}
