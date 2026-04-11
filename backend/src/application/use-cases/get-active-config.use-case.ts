import { Inject, Injectable } from '@nestjs/common';
import type { ConfigurationSnapshot } from 'src/domain/entities/configuration-snapshot.entity';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import {
  CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
  type IConfigSnapshotRepository,
} from 'src/domain/repositories/config-snapshot.repository';

@Injectable()
export class GetActiveConfigUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly repository: IConfigSnapshotRepository,
  ) {}
  async execute(): Promise<ConfigurationSnapshot> {
    const snapshot = await this.repository.findActiveSnapshot();

    if (!snapshot)
      throw new EntityNotFoundException('configuration snapshot', 'active');

    const payload = snapshot.deserializePayload();

    return snapshot;
  }
}
