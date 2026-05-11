import { Inject, Injectable } from '@nestjs/common';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type { IdentitySettingsInputDto } from '../dtos/identity-config-profile.dto.js';
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from '../ports/token-service.interface.js';
import { IdentityConfigMutationService } from '../services/identity-config-mutation.service.js';
import { IdentitySecretReferenceValidatorService } from '../services/identity-secret-reference-validator.service.js';

export interface UpdateIdentitySettingsCommand extends IdentitySettingsInputDto {
  accessToken: string;
}

@Injectable()
export class UpdateIdentitySettingsUseCase {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly mutationService: IdentityConfigMutationService,
    private readonly secretReferenceValidator: IdentitySecretReferenceValidatorService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(command: UpdateIdentitySettingsCommand) {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    return this.identityConfigRepository.mutate(async (config) => {
      const current = config.getSettings();
      const settings = IdentitySettings.create(
        command.portalAuthenticationProfileId === undefined
          ? current.getPortalAuthenticationProfileId()
          : command.portalAuthenticationProfileId,
        command.adminAuthenticationProfileId === undefined
          ? current.getAdminAuthenticationProfileId()
          : command.adminAuthenticationProfileId,
        new Date(),
        claims.sub,
        command.portalListener === undefined
          ? current.getPortalListener()
          : {
              enabled: command.portalListener.enabled ?? current.getPortalListener().getEnabled(),
              interfaceName: command.portalListener.interfaceName === undefined
                ? current.getPortalListener().getInterfaceName()
                : command.portalListener.interfaceName,
              zoneId: command.portalListener.zoneId === undefined
                ? current.getPortalListener().getZoneId()
                : command.portalListener.zoneId,
              bindAddress: command.portalListener.bindAddress === undefined
                ? current.getPortalListener().getBindAddress()
                : command.portalListener.bindAddress,
              bindPort: command.portalListener.bindPort ?? current.getPortalListener().getBindPort(),
            },
      );
      const next = this.mutationService.replaceSettings(config, settings);

      await this.secretReferenceValidator.validateActiveConfig(next);

      return next;
    });
  }
}
