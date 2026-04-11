import { Inject, Injectable } from '@nestjs/common';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import {
  CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
  type IConfigSnapshotRepository,
} from 'src/domain/repositories/config-snapshot.repository';
import { ExportConfigResponseDto } from '../dtos/export-confg-response.dto';

@Injectable()
export class ExportConfigUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
  ) {}

  async execute(): Promise<ExportConfigResponseDto> {
    const configSnapshot =
      await this.configSnapshotRepository.findActiveSnapshot();

    if (!configSnapshot)
      throw new EntityNotFoundException('Configuration snapshot', 'active');

    return {
      configSnapshot,
    };
  }
}
