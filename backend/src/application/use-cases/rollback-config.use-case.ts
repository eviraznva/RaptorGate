import { Inject, Injectable, Logger } from '@nestjs/common';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import {
  CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
  type IConfigSnapshotRepository,
} from '../../domain/repositories/config-snapshot.repository.js';
import {
  type IFirewallCertificateRepository,
  FIREWALL_CERTIFICATE_REPOSITORY_TOKEN,
} from '../../domain/repositories/firewall-certificate.repository.js';
import {
  type INatRulesRepository,
  NAT_RULES_REPOSITORY_TOKEN,
} from '../../domain/repositories/nat-rules.repository.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import {
  type IRulesRepository,
  RULES_REPOSITORY_TOKEN,
} from '../../domain/repositories/rules-repository.js';
import {
  type ISslBypassRepository,
  SSL_BYPASS_REPOSITORY_TOKEN,
} from '../../domain/repositories/ssl-bypass.repository.js';
import {
  type IZoneRepository,
  ZONE_REPOSITORY_TOKEN,
} from '../../domain/repositories/zone.repository.js';
import {
  type IZoneInterfaceRepository,
  ZONE_INTERFACE_REPOSITORY_TOKEN,
} from '../../domain/repositories/zone-interface.repository.js';
import {
  type IZonePairRepository,
  ZONE_PAIR_REPOSITORY_TOKEN,
} from '../../domain/repositories/zone-pair.repository.js';
import { IdentityConfigJsonMapper } from '../../infrastructure/persistence/mappers/identity-config-json.mapper.js';
import type { RollbackConfigDto } from '../dtos/rollback-config.dto.js';
import type { RollbackConfigSnapshotResponseDto } from '../dtos/rollback-config-response.dto.js';
import {
  CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN,
  type IConfigSnapshotPushService,
} from '../ports/config-snapshot-push-service.interface.js';
import { IdentitySecretReferenceValidatorService } from '../services/identity-secret-reference-validator.service.js';

@Injectable()
export class RollbackConfigUseCase {
  private readonly logger = new Logger(RollbackConfigUseCase.name);

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
    @Inject(ZONE_INTERFACE_REPOSITORY_TOKEN)
    private readonly zoneInterfaceRepository: IZoneInterfaceRepository,
    @Inject(FIREWALL_CERTIFICATE_REPOSITORY_TOKEN)
    private readonly firewallCertificateRepository: IFirewallCertificateRepository,
    @Inject(SSL_BYPASS_REPOSITORY_TOKEN)
    private readonly sslBypassRepository: ISslBypassRepository,
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly identitySecretReferenceValidator: IdentitySecretReferenceValidatorService,
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
  ) {}

  async execute(
    dto: RollbackConfigDto,
  ): Promise<RollbackConfigSnapshotResponseDto> {
    const configSnapshot = await this.configSnapshotRepository.findById(dto.id);
    if (!configSnapshot)
      throw new EntityNotFoundException('Config snpshot', dto.id);

    const configBundle = configSnapshot.deserializePayload();

    await this.zoneRepository.overwriteAll(configBundle.bundle.zones.items);
    await this.zoneInterfaceRepository.overwriteAll(
      configBundle.bundle.zone_interfaces.items,
    );
    await this.zonePairRepository.overwriteAll(
      configBundle.bundle.zone_pairs.items,
    );
    await this.rulesRepository.overwriteAll(configBundle.bundle.rules.items);
    await this.natRulesRepository.overwriteAll(
      configBundle.bundle.nat_rules.items,
    );
    await this.firewallCertificateRepository.overwriteAll(
      configBundle.bundle.firewall_certificates.items,
    );
    await this.sslBypassRepository.overwriteAll(
      configBundle.bundle.ssl_bypass_list.items,
    );
    const identityConfig = IdentityConfigJsonMapper.payloadToDomain(
      configBundle.bundle.identity_config ??
        IdentityConfigJsonMapper.recordToPayload(
          IdentityConfigJsonMapper.emptyRecord(),
        ),
    );
    await this.identitySecretReferenceValidator.validateActiveConfig(
      identityConfig,
    );
    await this.identityConfigRepository.overwrite(identityConfig);

    const currentActiveSnapshot =
      await this.configSnapshotRepository.findActiveSnapshot();
    if (
      currentActiveSnapshot &&
      currentActiveSnapshot.getId() !== configSnapshot.getId()
    ) {
      currentActiveSnapshot.setIsActive(false);
      await this.configSnapshotRepository.save(currentActiveSnapshot);
    }

    configSnapshot.setIsActive(true);
    await this.configSnapshotRepository.save(configSnapshot);

    await this.configSnapshotPushService.pushActiveConfigSnapshot(
      configSnapshot,
      'rollback',
    );

    this.logger.log({
      event: "config_snapshot.rollback.succeeded",
      message: "configuration snapshot rolled back",
      snapshotId: configSnapshot.getId(),
      versionNumber: configSnapshot.getVersionNumber(),
      checksum: configSnapshot.getChecksum().getValue(),
      counts: {
        rules: configBundle.bundle.rules.items.length,
        zones: configBundle.bundle.zones.items.length,
        zoneInterfaces: configBundle.bundle.zone_interfaces.items.length,
        zonePairs: configBundle.bundle.zone_pairs.items.length,
        natRules: configBundle.bundle.nat_rules.items.length,
      },
    });

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
