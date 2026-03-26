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
import {
  ZonePair,
  ZonePairPolicy,
} from '../../domain/entities/zone-pair.entity.js';
import { FirewallRule } from '../../domain/entities/firewall-rule.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { Priority } from '../../domain/value-objects/priority.vo.js';
import { NatType } from '../../domain/value-objects/nat-type.vo.js';
import { RollbackConfigDto } from '../dtos/rollback-config.dto.js';
import { NatRule } from '../../domain/entities/nat-rule.entity.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { Zone } from '../../domain/entities/zone.entity.js';
import { Injectable, Inject } from '@nestjs/common';

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

  async execute(dto: RollbackConfigDto): Promise<void> {
    const configSnapshot = await this.configSnapshotRepository.findById(dto.id);
    if (!configSnapshot)
      throw new EntityNotFoundException('Config snpshot', dto.id);

    const configBundle = configSnapshot.deserializePayload();

    // const newZones = configBundle.bundle.zones.items.map((zone) =>
    //   Zone.create(
    //     zone.id,
    //     zone.name,
    //     zone.description || null,
    //     zone.isActive,
    //     new Date(zone.createdAt),
    //     zone.createdBy,
    //   ),
    // );

    // const newZonePairs = configBundle.bundle.zone_pairs.items.map((zonePair) =>
    //   ZonePair.create(
    //     zonePair.id,
    //     zonePair.srcZoneId,
    //     zonePair.dstZoneID,
    //     zonePair.defaultPolicy as ZonePairPolicy,
    //     new Date(zonePair.createdAt),
    //     zonePair.createdBy,
    //   ),
    // );

    // const newRules = configBundle.bundle.rules.items.map((rule) =>
    //   FirewallRule.create(
    //     rule.id,
    //     rule.name,
    //     rule.description || null,
    //     rule.zonePairId,
    //     rule.isActive,
    //     rule.content,
    //     Priority.create(rule.priority),
    //     new Date(rule.createdAt),
    //     new Date(rule.updatedAt),
    //     rule.createdBy,
    //   ),
    // );

    // const newNatRules = configBundle.bundle.nat_rules.items.map((natRule) =>
    //   NatRule.create(
    //     natRule.id,
    //     NatType.create(natRule.type),
    //     natRule.isActive,
    //     natRule.srcIp != null ? IpAddress.create(natRule.srcIp) : null,
    //     natRule.dstIp != null ? IpAddress.create(natRule.dstIp) : null,
    //     natRule.srcPort != null ? Port.create(natRule.srcPort) : null,
    //     natRule.dstPort != null ? Port.create(natRule.dstPort) : null,
    //     natRule.translatedIp != null
    //       ? IpAddress.create(natRule.translatedIp)
    //       : null,
    //     natRule.translatedPort != null
    //       ? Port.create(natRule.translatedPort)
    //       : null,
    //     Priority.create(natRule.priority),
    //     new Date(natRule.createdAt),
    //     new Date(natRule.updatedAt),
    //   ),
    // );

    await this.zoneRepository.overwriteAll(configBundle.bundle.zones.items);
    await this.zonePairRepository.overwriteAll(
      configBundle.bundle.zone_pairs.items,
    );
    await this.rulesRepository.overwriteAll(configBundle.bundle.rules.items);
    await this.natRulesRepository.overwriteAll(
      configBundle.bundle.nat_rules.items,
    );
  }
}
