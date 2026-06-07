import { hash, randomUUID } from 'node:crypto';
import { BadRequestException, Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import { Checksum } from '../../domain/value-objects/checksum.vo.js';
import {
  type ConfigSnapshotPayload,
  type DecryptionFailureCacheConfigPayload,
  normalizeTlsInspectionPolicy,
} from '../../domain/value-objects/config-snapshot-payload.interface.js';
import { SnapshotType } from '../../domain/value-objects/snapshot-type.vo.js';
import type {
  DecryptionFailurePolicyDto,
  DecryptionFailurePolicyResponseDto,
} from '../dtos/decryption-failure-policy.dto.js';
import type { IConfigSnapshotPushService } from '../ports/config-snapshot-push-service.interface.js';
import { CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN } from '../ports/config-snapshot-push-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';

export interface UpdateDecryptionFailurePolicyCommand extends DecryptionFailurePolicyDto {
  accessToken: string;
}

@Injectable()
export class UpdateDecryptionFailurePolicyUseCase {
  private readonly logger = new Logger(UpdateDecryptionFailurePolicyUseCase.name);

  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(command: UpdateDecryptionFailurePolicyCommand): Promise<DecryptionFailurePolicyResponseDto> {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const activeSnapshot = await this.configSnapshotRepository.findActiveSnapshot();
    if (!activeSnapshot) throw new NotFoundException('Active configuration snapshot not found');

    const decryptionFailureCache = this.normalizeCommand(command);
    const payload = activeSnapshot.deserializePayload();
    const nextPayload = this.withDecryptionFailureCache(payload, decryptionFailureCache);
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
      'Update TLS decryption failure policy',
      new Date(),
      claims.sub,
    );

    await this.configSnapshotRepository.save(nextSnapshot);
    activeSnapshot.setIsActive(false);
    await this.configSnapshotRepository.save(activeSnapshot);
    await this.configSnapshotPushService.pushActiveConfigSnapshot(
      nextSnapshot,
      'decryption_failure_policy_update',
    );

    this.logger.log({
      event: 'ssl.decryption_failure_policy.updated',
      message: 'TLS decryption failure policy updated',
      actorId: claims.sub,
      snapshotId: nextSnapshot.getId(),
      enabled: decryptionFailureCache.enabled,
      action: decryptionFailureCache.action,
    });

    return {
      decryptionFailurePolicy: {
        enabled: decryptionFailureCache.enabled,
        failureThreshold: decryptionFailureCache.failure_threshold,
        failureWindowSec: decryptionFailureCache.failure_window_sec,
        localExclusionTtlSec: decryptionFailureCache.local_exclusion_ttl_sec,
        maxEntries: decryptionFailureCache.max_entries,
        action: decryptionFailureCache.action === 'cache_and_bypass' ? 'cacheAndBypass' : 'block',
      },
    };
  }

  private normalizeCommand(command: DecryptionFailurePolicyDto): DecryptionFailureCacheConfigPayload {
    if (!Number.isInteger(command.failureThreshold) || command.failureThreshold < 1 || command.failureThreshold > 1000) {
      throw new BadRequestException('failureThreshold must be in range 1..1000');
    }
    if (!Number.isInteger(command.failureWindowSec) || command.failureWindowSec < 1) {
      throw new BadRequestException('failureWindowSec must be at least 1');
    }
    if (!Number.isInteger(command.localExclusionTtlSec) || command.localExclusionTtlSec < 1) {
      throw new BadRequestException('localExclusionTtlSec must be at least 1');
    }
    if (!Number.isInteger(command.maxEntries) || command.maxEntries < 1) {
      throw new BadRequestException('maxEntries must be at least 1');
    }
    if (command.action !== 'block' && command.action !== 'cacheAndBypass') {
      throw new BadRequestException('action must be block or cacheAndBypass');
    }

    return {
      version: 1,
      enabled: command.enabled,
      failure_threshold: command.failureThreshold,
      failure_window_sec: command.failureWindowSec,
      local_exclusion_ttl_sec: command.localExclusionTtlSec,
      max_entries: command.maxEntries,
      action: command.action === 'cacheAndBypass' ? 'cache_and_bypass' : 'block',
    };
  }

  private withDecryptionFailureCache(
    payload: ConfigSnapshotPayload,
    decryptionFailureCache: DecryptionFailureCacheConfigPayload,
  ): ConfigSnapshotPayload {
    const tlsInspectionPolicy = normalizeTlsInspectionPolicy(
      payload.bundle.tls_inspection_policy,
    );

    return {
      bundle: {
        ...payload.bundle,
        tls_inspection_policy: {
          ...tlsInspectionPolicy,
          decryption_failure_cache: decryptionFailureCache,
        },
      },
    };
  }
}
