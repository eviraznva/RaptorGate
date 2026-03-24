import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from 'src/domain/repositories/config-snapshot.repository';
import type { IConfigSnapshotRepository } from 'src/domain/repositories/config-snapshot.repository';
import { Inject, Injectable } from '@nestjs/common';
import { GetConfigHistoryDto } from '../dtos/get-config-history.dto';

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
