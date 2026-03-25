import { mapPayloadToConfigResponse } from 'src/infrastructure/persistence/mappers/config-payload.mapper';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from 'src/domain/repositories/config-snapshot.repository';
import type { IConfigSnapshotRepository } from 'src/domain/repositories/config-snapshot.repository';
import { ConfigSectionVersions } from 'src/infrastructure/grpc/generated/config/config_models';
import { ConfigResponse } from 'src/infrastructure/grpc/generated/config/config_service';
import { Inject, Injectable } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';

@Injectable()
export class GetActiveConfigUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly repository: IConfigSnapshotRepository,
  ) {}
  async execute(
    correlationId: string,
    knownVersions: ConfigSectionVersions | undefined,
  ): Promise<ConfigResponse> {
    const snapshot = await this.repository.findActiveSnapshot();

    if (!snapshot) {
      throw new RpcException({
        code: status.NOT_FOUND,
        message: 'No active configuration snapshot found',
      });
    }

    const payload = snapshot.deserializePayload();

    return mapPayloadToConfigResponse(
      payload,
      correlationId,
      snapshot.getVersionNumber(),
      snapshot.getChecksum().getValue(),
      knownVersions,
    );
  }
}
