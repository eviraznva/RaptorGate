import { Inject, Injectable } from '@nestjs/common';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import {
  normalizeTlsInspectionPolicy,
} from '../../domain/value-objects/config-snapshot-payload.interface.js';
import type { DecryptionMirrorConfigResponseDto } from '../dtos/decryption-mirror-config.dto.js';

@Injectable()
export class GetDecryptionMirrorConfigUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
  ) {}

  async execute(): Promise<DecryptionMirrorConfigResponseDto> {
    const activeSnapshot = await this.configSnapshotRepository.findActiveSnapshot();
    const policy = normalizeTlsInspectionPolicy(
      activeSnapshot?.deserializePayload().bundle.tls_inspection_policy,
    );

    return {
      decryptionMirror: {
        enabled: policy.decryption_mirror.enabled,
        targetHost: policy.decryption_mirror.target_host,
        targetPort: policy.decryption_mirror.target_port,
        includeClientToServer: policy.decryption_mirror.include_client_to_server,
        includeServerToClient: policy.decryption_mirror.include_server_to_client,
        forwardedOnly: policy.decryption_mirror.forwarded_only,
        maxSessionBytes: policy.decryption_mirror.max_session_bytes,
      },
    };
  }
}
