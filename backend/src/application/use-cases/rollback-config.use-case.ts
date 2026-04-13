import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { FirewallCertificate } from '../../domain/entities/firewall-certificate.entity.js';
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
  type IZonePairRepository,
  ZONE_PAIR_REPOSITORY_TOKEN,
} from '../../domain/repositories/zone-pair.repository.js';
import type { RollbackConfigDto } from '../dtos/rollback-config.dto.js';
import type { RollbackConfigSnapshotResponseDto } from '../dtos/rollback-config-response.dto.js';
import {
  CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN,
  type IConfigSnapshotPushService,
} from '../ports/config-snapshot-push-service.interface.js';
import { SecretStore } from '../../infrastructure/persistence/secret-store.js';

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
    @Inject(FIREWALL_CERTIFICATE_REPOSITORY_TOKEN)
    private readonly firewallCertificateRepository: IFirewallCertificateRepository,
    @Inject(SSL_BYPASS_REPOSITORY_TOKEN)
    private readonly sslBypassRepository: ISslBypassRepository,
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
    private readonly secretStore: SecretStore,
  ) {}

  async execute(
    dto: RollbackConfigDto,
  ): Promise<RollbackConfigSnapshotResponseDto> {
    const configSnapshot = await this.configSnapshotRepository.findById(dto.id);
    if (!configSnapshot)
      throw new EntityNotFoundException('Config snpshot', dto.id);

    const configBundle = configSnapshot.deserializePayload();
    await this.ensureTlsSecretsExist(
      configBundle.bundle.firewall_certificates.items,
    );

    await this.zoneRepository.overwriteAll(configBundle.bundle.zones.items);
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
    await this.configSnapshotPushService.pushActiveConfigSnapshot(
      configSnapshot,
      'rollback',
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

  private async ensureTlsSecretsExist(
    certificates: FirewallCertificate[],
  ): Promise<void> {
    const refs = certificates
      .filter(
        (certificate) =>
          certificate.getCertType() === 'TLS_SERVER' &&
          certificate.getPrivateKeyRef().length > 0,
      )
      .map((certificate) => certificate.getPrivateKeyRef());

    if (refs.length > 0 && !this.secretStore.isConfigured()) {
      throw new BadRequestException(
        'BACKEND_SECRET_ENCRYPTION_KEY is required for active TLS server certificates',
      );
    }

    const missing = await this.secretStore.missing(refs);
    if (missing.length > 0) {
      throw new BadRequestException(
        `Missing TLS private key secrets for refs: ${missing.join(', ')}`,
      );
    }
  }
}
