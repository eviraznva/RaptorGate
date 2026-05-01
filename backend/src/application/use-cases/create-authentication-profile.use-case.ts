import { Inject, Injectable } from '@nestjs/common';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
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

export interface CreateAuthenticationProfileCommand
  extends AuthenticationProfileInputDto {
  accessToken: string;
}

@Injectable()
export class CreateAuthenticationProfileUseCase {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly mutationService: IdentityConfigMutationService,
    private readonly secretReferenceValidator: IdentitySecretReferenceValidatorService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(command: CreateAuthenticationProfileCommand) {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const now = new Date();
    const profile = IdentityAuthenticationProfile.create(
      crypto.randomUUID(),
      command.name,
      command.description,
      command.isActive,
      command.provider,
      command.radiusProfileId,
      command.ldapProfileId,
      command.groupSource,
      command.sessionTtlSeconds,
      now,
      now,
      claims.sub,
    );
    return this.identityConfigRepository.mutate(async (config) => {
      const next = this.mutationService.addAuthenticationProfile(config, profile);

      await this.secretReferenceValidator.validateActiveConfig(next);

      return next;
    });
  }
}
