import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import {
  CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
  type IConfigSnapshotRepository,
} from '../../domain/repositories/config-snapshot.repository.js';
import {
  NAT_RULES_REPOSITORY_TOKEN,
  type INatRulesRepository,
} from '../../domain/repositories/nat-rules.repository.js';
import {
  ZONE_PAIR_REPOSITORY_TOKEN,
  type IZonePairRepository,
} from '../../domain/repositories/zone-pair.repository.js';
import {
  RULES_REPOSITORY_TOKEN,
  type IRulesRepository,
} from '../../domain/repositories/rules-repository.js';
import {
  ZONE_REPOSITORY_TOKEN,
  type IZoneRepository,
} from '../../domain/repositories/zone.repository.js';
import { RollbackConfigDto } from '../dtos/rollback-config.dto.js';
import { Injectable, Inject } from '@nestjs/common';
import { RollbackConfigSnapshotResponseDto } from '../dtos/rollback-config-response.dto.js';

@Injectable()
export class RollbackConfigUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
  ) {}

  async execute(
    dto: RollbackConfigDto,
  ): Promise<RollbackConfigSnapshotResponseDto> {
    const configSnapshot = await this.configSnapshotRepository.findById(dto.id);
    if (!configSnapshot)
      throw new EntityNotFoundException('Config snpshot', dto.id);

    const configBundle = configSnapshot.deserializePayload();

    await this.zoneRepository.overwriteAll(configBundle.bundle.zones.items);
    await this.zonePairRepository.overwriteAll(
      configBundle.bundle.zone_pairs.items,
    );
    await this.rulesRepository.overwriteAll(configBundle.bundle.rules.items);
    await this.natRulesRepository.overwriteAll(
      configBundle.bundle.nat_rules.items,
    );

    return {
      id: configSnapshot.getId(),
      versionNumber: configSnapshot.getVersionNumber(),
      snapshotType: configSnapshot.getSnapshotType().getValue(),
      checksum: configSnapshot.getChecksum().getValue(),
      isActive: configSnapshot.getIsActive(),
      payloadJson: configSnapshot.deserializePayload(),
      changesSummary: configSnapshot.getChangesSummary(),
      createdAt: configSnapshot.getCreatedAt(),
      createdBy: configSnapshot.getCreatedBy(),
    };
  }
}
