import { Inject, Injectable } from '@nestjs/common';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import {
  normalizeTlsInspectionPolicy,
} from '../../domain/value-objects/config-snapshot-payload.interface.js';
import type {
  DecryptionFailurePolicyResponseDto,
} from '../dtos/decryption-failure-policy.dto.js';

@Injectable()
export class GetDecryptionFailurePolicyUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
  ) {}

  async execute(): Promise<DecryptionFailurePolicyResponseDto> {
    const activeSnapshot = await this.configSnapshotRepository.findActiveSnapshot();
    const policy = normalizeTlsInspectionPolicy(
      activeSnapshot?.deserializePayload().bundle.tls_inspection_policy,
    );
    const config = policy.decryption_failure_cache;

    return {
      decryptionFailurePolicy: {
        enabled: config.enabled,
        failureThreshold: config.failure_threshold,
        failureWindowSec: config.failure_window_sec,
        localExclusionTtlSec: config.local_exclusion_ttl_sec,
        maxEntries: config.max_entries,
        action: config.action === 'cache_and_bypass' ? 'cacheAndBypass' : 'block',
      },
    };
  }
}
