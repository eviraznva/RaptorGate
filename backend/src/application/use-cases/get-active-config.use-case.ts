import { Inject, Injectable } from '@nestjs/common';
import type { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import {
  CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
  type IConfigSnapshotRepository,
} from '../../domain/repositories/config-snapshot.repository.js';

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
