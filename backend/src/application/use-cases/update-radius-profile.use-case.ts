import { Inject, Injectable } from '@nestjs/common';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { IdentityProfileNotFoundException } from '../../domain/exceptions/identity-profile-not-found.exception.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type { RadiusProfileInputDto } from '../dtos/identity-config-profile.dto.js';
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from '../ports/token-service.interface.js';
import { IdentityConfigMutationService } from '../services/identity-config-mutation.service.js';
import { IdentitySecretReferenceValidatorService } from '../services/identity-secret-reference-validator.service.js';

export interface UpdateRadiusProfileCommand extends RadiusProfileInputDto {
  accessToken: string;
  id: string;
}

@Injectable()
export class UpdateRadiusProfileUseCase {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly mutationService: IdentityConfigMutationService,
    private readonly secretReferenceValidator: IdentitySecretReferenceValidatorService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(command: UpdateRadiusProfileCommand) {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    return this.identityConfigRepository.mutate(async (config) => {
      const existing = config
        .getRadiusServerProfiles()
        .find((profile) => profile.getId() === command.id);
      if (!existing) throw new IdentityProfileNotFoundException('radius', command.id);

      const profile = RadiusServerProfile.create(
        command.id,
        command.name,
        command.description,
        command.isActive,
        command.host,
        command.port,
        command.sharedSecretRef,
        command.timeoutMs,
        command.retries,
        command.nasIp,
        command.nasIdentifier,
        command.calledStationId,
        existing.getCreatedAt(),
        new Date(),
        existing.getCreatedBy(),
      );
      const next = this.mutationService.replaceRadiusProfile(config, profile);

      await this.secretReferenceValidator.validateActiveConfig(next);

      return next;
    });
  }
}
