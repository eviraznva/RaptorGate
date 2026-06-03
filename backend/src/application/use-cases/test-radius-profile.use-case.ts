import { Inject, Injectable } from '@nestjs/common';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { IdentityProfileNotFoundException } from '../../domain/exceptions/identity-profile-not-found.exception.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type { IdentityProviderTestResponseDto } from '../dtos/identity-provider-test.dto.js';
import {
  type IRadiusAuthenticator,
  type RadiusAuthServerOptions,
  RADIUS_AUTHENTICATOR_TOKEN,
} from '../ports/radius-authenticator.interface.js';
import {
  type ISecretResolverService,
  SECRET_RESOLVER_SERVICE_TOKEN,
} from '../ports/secret-resolver.service.js';
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from '../ports/token-service.interface.js';
import { radiusOptionsFromProfile } from '../services/authentication-provider-options.js';

export interface TestRadiusProfileCommand {
  accessToken: string;
  id: string;
  username: string;
  password: string;
  callingStationId: string;
}

@Injectable()
export class TestRadiusProfileUseCase {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    @Inject(SECRET_RESOLVER_SERVICE_TOKEN)
    private readonly secretResolver: ISecretResolverService,
    @Inject(RADIUS_AUTHENTICATOR_TOKEN)
    private readonly radiusAuthenticator: IRadiusAuthenticator,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(
    command: TestRadiusProfileCommand,
  ): Promise<IdentityProviderTestResponseDto> {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const config = await this.identityConfigRepository.find();
    const profile = config
      .getRadiusServerProfiles()
      .find((item) => item.getId() === command.id);
    if (!profile) throw new IdentityProfileNotFoundException('radius', command.id);

    const servers: RadiusAuthServerOptions[] = [];
    for (const endpoint of profile.getServers()) {
      if (!endpoint.getIsActive()) continue;
      const secret = await this.secretResolver.resolve(endpoint.getSharedSecretRef());
      servers.push({
        name: endpoint.getName(),
        host: endpoint.getHost(),
        port: endpoint.getPort(),
        secret: secret.getValue(),
        priority: endpoint.getPriority(),
      });
    }
    const startedAt = Date.now();
    const result = await this.radiusAuthenticator.authenticate({
      username: command.username,
      password: command.password,
      callingStationId: command.callingStationId,
      profile: radiusOptionsFromProfile(profile, servers),
    });
    const latencyMs = Date.now() - startedAt;

    if (result.kind === 'accept') {
      return {
        result: 'accept',
        latencyMs,
        message: 'RADIUS Access-Accept',
        groups: result.groups,
      };
    }
    if (result.kind === 'reject') {
      return {
        result: 'reject',
        latencyMs,
        message: result.reason,
      };
    }
    if (result.kind === 'timeout') {
      return {
        result: 'timeout',
        latencyMs,
        message: 'RADIUS request timed out',
      };
    }

    return {
      result: 'error',
      latencyMs,
      message: result.message,
    };
  }
}
