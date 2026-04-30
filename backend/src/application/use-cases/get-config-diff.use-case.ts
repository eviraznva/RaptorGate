import { Inject, Injectable } from '@nestjs/common';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import {
  CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
  type IConfigSnapshotRepository,
} from '../../domain/repositories/config-snapshot.repository.js';
import type {
  ConfigDiffSnapshotMeta,
  GetConfigDiffDto,
} from '../dtos/get-config-diff.dto.js';
import { ConfigSnapshotDiffService } from '../services/config-snapshot-diff.service.js';

type GetConfigDiffInput = {
  baseId: string;
  targetId: string;
};

@Injectable()
export class GetConfigDiffUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
    @Inject(ConfigSnapshotDiffService)
    private readonly configSnapshotDiffService: ConfigSnapshotDiffService,
  ) {}

  async execute(dto: GetConfigDiffInput): Promise<GetConfigDiffDto> {
    const [baseSnapshot, targetSnapshot] = await Promise.all([
      this.configSnapshotRepository.findById(dto.baseId),
      this.configSnapshotRepository.findById(dto.targetId),
    ]);

    if (!baseSnapshot) {
      throw new EntityNotFoundException('Configuration snapshot', dto.baseId);
    }

    if (!targetSnapshot) {
      throw new EntityNotFoundException('Configuration snapshot', dto.targetId);
    }

    const diff = this.configSnapshotDiffService.diff(
      baseSnapshot.deserializePayload(),
      targetSnapshot.deserializePayload(),
    );

    return {
      baseSnapshot: this.toSnapshotMeta(baseSnapshot),
      targetSnapshot: this.toSnapshotMeta(targetSnapshot),
      summary: diff.summary,
      changes: diff.changes,
    };
  }

  private toSnapshotMeta(
    snapshot: ConfigurationSnapshot,
  ): ConfigDiffSnapshotMeta {
    return {
      id: snapshot.getId(),
      versionNumber: snapshot.getVersionNumber(),
      checksum: snapshot.getChecksum().getValue(),
      createdAt: snapshot.getCreatedAt().toISOString(),
    };
  }
}
