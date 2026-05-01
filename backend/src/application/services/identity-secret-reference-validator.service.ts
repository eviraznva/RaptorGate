import { Inject, Injectable, Logger } from '@nestjs/common';
import { SecretReferenceMissingException } from '../../domain/exceptions/secret-reference-missing.exception.js';
import {
  type ISecretStoreRepository,
  SECRET_STORE_REPOSITORY_TOKEN,
} from '../../domain/repositories/secret-store.repository.js';
import type { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';

@Injectable()
export class IdentitySecretReferenceValidatorService {
  private readonly logger = new Logger(IdentitySecretReferenceValidatorService.name);

  constructor(
    @Inject(SECRET_STORE_REPOSITORY_TOKEN)
    private readonly secretStoreRepository: ISecretStoreRepository,
  ) {}

  async validateActiveConfig(config: IdentityConfiguration): Promise<void> {
    const refs = new Set<string>();

    for (const profile of config.getRadiusServerProfiles()) {
      refs.add(profile.getSharedSecretRef());
    }

    for (const profile of config.getLdapServerProfiles()) {
      refs.add(profile.getBindPasswordRef());
    }

    // TODO(Issue D): include auth profile secret refs if admin auth adds them.
    for (const ref of refs) {
      await this.validateRef(ref);
    }
  }

  private async validateRef(ref: string): Promise<void> {
    if (ref.startsWith('env:')) {
      this.logger.warn({
        event: 'identity.secret_reference.env_allowed',
        message: 'identity config uses environment secret reference',
        ref,
      });
      return;
    }

    if (!(await this.secretStoreRepository.exists(ref))) {
      throw new SecretReferenceMissingException(ref);
    }
  }
}
