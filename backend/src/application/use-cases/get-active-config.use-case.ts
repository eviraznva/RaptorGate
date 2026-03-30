import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { RpcException } from '@nestjs/microservices';
import { Inject, Injectable } from '@nestjs/common';
import { status } from '@grpc/grpc-js';

@Injectable()
export class GetActiveConfigUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly repository: IConfigSnapshotRepository,
  ) {}
  async execute(): Promise<ConfigurationSnapshot> {
    const snapshot = await this.repository.findActiveSnapshot();

    if (!snapshot) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'No active configuration snapshot found',
      });
    }

    const payload = snapshot.deserializePayload();

    return snapshot;
  }
}
