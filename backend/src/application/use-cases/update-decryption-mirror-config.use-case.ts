import { hash, randomUUID } from 'node:crypto';
import { BadRequestException, Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import { Checksum } from '../../domain/value-objects/checksum.vo.js';
import {
  type ConfigSnapshotPayload,
  type DecryptionMirrorConfigPayload,
  normalizeTlsInspectionPolicy,
} from '../../domain/value-objects/config-snapshot-payload.interface.js';
import { SnapshotType } from '../../domain/value-objects/snapshot-type.vo.js';
import type {
  DecryptionMirrorConfigDto,
  DecryptionMirrorConfigResponseDto,
} from '../dtos/decryption-mirror-config.dto.js';
import type { IConfigSnapshotPushService } from '../ports/config-snapshot-push-service.interface.js';
import { CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN } from '../ports/config-snapshot-push-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';

export interface UpdateDecryptionMirrorConfigCommand extends DecryptionMirrorConfigDto {
  accessToken: string;
}

@Injectable()
export class UpdateDecryptionMirrorConfigUseCase {
  private readonly logger = new Logger(UpdateDecryptionMirrorConfigUseCase.name);

  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(command: UpdateDecryptionMirrorConfigCommand): Promise<DecryptionMirrorConfigResponseDto> {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const activeSnapshot = await this.configSnapshotRepository.findActiveSnapshot();
    if (!activeSnapshot) throw new NotFoundException('Active configuration snapshot not found');

    const decryptionMirror = this.normalizeCommand(command);
    const payload = activeSnapshot.deserializePayload();
    const nextPayload = this.withDecryptionMirror(payload, decryptionMirror);
    const allSnapshots = await this.configSnapshotRepository.findAllSnapshots();
    const highestVersionNumber = allSnapshots.reduce((prev, curr) => {
      if (curr.getVersionNumber() > prev) return curr.getVersionNumber();
      return prev;
    }, 0);
    const checksum = hash('sha256', JSON.stringify(nextPayload));
    const nextSnapshot = ConfigurationSnapshot.create(
      randomUUID(),
      highestVersionNumber + 1,
      SnapshotType.create('auto_save'),
      Checksum.create(checksum),
      true,
      nextPayload,
      'Update SSL decryption mirror config',
      new Date(),
      claims.sub,
    );

    await this.configSnapshotRepository.save(nextSnapshot);
    activeSnapshot.setIsActive(false);
    await this.configSnapshotRepository.save(activeSnapshot);
    await this.configSnapshotPushService.pushActiveConfigSnapshot(
      nextSnapshot,
      'decryption_mirror_update',
    );

    this.logger.log({
      event: 'ssl.decryption_mirror.config_updated',
      message: 'SSL decryption mirror config updated',
      actorId: claims.sub,
      snapshotId: nextSnapshot.getId(),
      enabled: decryptionMirror.enabled,
      targetHost: decryptionMirror.target_host,
      targetPort: decryptionMirror.target_port,
    });

    return {
      decryptionMirror: {
        enabled: decryptionMirror.enabled,
        targetHost: decryptionMirror.target_host,
        targetPort: decryptionMirror.target_port,
        includeClientToServer: decryptionMirror.include_client_to_server,
        includeServerToClient: decryptionMirror.include_server_to_client,
        forwardedOnly: decryptionMirror.forwarded_only,
        maxSessionBytes: decryptionMirror.max_session_bytes,
      },
    };
  }

  private normalizeCommand(command: DecryptionMirrorConfigDto): DecryptionMirrorConfigPayload {
    const targetHost = command.targetHost.trim();
    if (command.enabled && targetHost.length === 0) {
      throw new BadRequestException('targetHost is required when mirror is enabled');
    }
    if (!Number.isInteger(command.targetPort) || command.targetPort < 0 || command.targetPort > 65535) {
      throw new BadRequestException('targetPort must be in range 0..65535');
    }
    if (command.enabled && (command.targetPort < 1 || command.targetPort > 65535)) {
      throw new BadRequestException('targetPort must be in range 1..65535 when mirror is enabled');
    }
    if (command.enabled && !command.includeClientToServer && !command.includeServerToClient) {
      throw new BadRequestException('At least one mirror direction must be enabled');
    }
    if (!Number.isInteger(command.maxSessionBytes) || command.maxSessionBytes < 1) {
      throw new BadRequestException('maxSessionBytes must be at least 1');
    }

    return {
      enabled: command.enabled,
      target_host: targetHost,
      target_port: command.targetPort,
      include_client_to_server: command.includeClientToServer,
      include_server_to_client: command.includeServerToClient,
      forwarded_only: command.forwardedOnly,
      max_session_bytes: command.maxSessionBytes,
    };
  }

  private withDecryptionMirror(
    payload: ConfigSnapshotPayload,
    decryptionMirror: DecryptionMirrorConfigPayload,
  ): ConfigSnapshotPayload {
    const tlsInspectionPolicy = normalizeTlsInspectionPolicy(
      payload.bundle.tls_inspection_policy,
    );

    return {
      bundle: {
        ...payload.bundle,
        tls_inspection_policy: {
          ...tlsInspectionPolicy,
          decryption_mirror: decryptionMirror,
        },
      },
    };
  }
}
