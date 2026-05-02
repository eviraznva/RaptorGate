import { Inject, Injectable } from '@nestjs/common';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { IdentityProfileNotFoundException } from '../../domain/exceptions/identity-profile-not-found.exception.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type { AuthenticationProfileInputDto } from '../dtos/identity-config-profile.dto.js';
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from '../ports/token-service.interface.js';
import { IdentityConfigMutationService } from '../services/identity-config-mutation.service.js';
import { IdentitySecretReferenceValidatorService } from '../services/identity-secret-reference-validator.service.js';

export interface UpdateAuthenticationProfileCommand
  extends AuthenticationProfileInputDto {
  accessToken: string;
  id: string;
}

@Injectable()
export class UpdateAuthenticationProfileUseCase {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly mutationService: IdentityConfigMutationService,
    private readonly secretReferenceValidator: IdentitySecretReferenceValidatorService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(command: UpdateAuthenticationProfileCommand) {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    return this.identityConfigRepository.mutate(async (config) => {
      const existing = config
        .getAuthenticationProfiles()
        .find((profile) => profile.getId() === command.id);
      if (!existing) {
        throw new IdentityProfileNotFoundException('authentication', command.id);
      }

      const profile = IdentityAuthenticationProfile.create(
        command.id,
        command.name,
        command.description,
        command.isActive,
        command.provider,
        command.radiusProfileId,
        command.ldapProfileId,
        command.groupSource,
        command.sessionTtlSeconds,
        existing.getCreatedAt(),
        new Date(),
        existing.getCreatedBy(),
        command.adminRoleMappings ?? [],
      );
      const next = this.mutationService.replaceAuthenticationProfile(
        config,
        profile,
      );

      await this.secretReferenceValidator.validateActiveConfig(next);

      return next;
    });
  }
}
