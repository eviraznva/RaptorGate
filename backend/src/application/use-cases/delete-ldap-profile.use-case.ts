import { Inject, Injectable } from '@nestjs/common';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from '../ports/token-service.interface.js';
import { IdentityConfigMutationService } from '../services/identity-config-mutation.service.js';
import { IdentitySecretReferenceValidatorService } from '../services/identity-secret-reference-validator.service.js';

export interface DeleteLdapProfileCommand {
  accessToken: string;
  id: string;
}

@Injectable()
export class DeleteLdapProfileUseCase {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly mutationService: IdentityConfigMutationService,
    private readonly secretReferenceValidator: IdentitySecretReferenceValidatorService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(command: DeleteLdapProfileCommand) {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    return this.identityConfigRepository.mutate(async (config) => {
      const next = this.mutationService.deleteLdapProfile(config, command.id);

      await this.secretReferenceValidator.validateActiveConfig(next);

      return next;
    });
  }
}
