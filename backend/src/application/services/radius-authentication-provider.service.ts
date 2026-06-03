import { Inject, Injectable, Logger } from '@nestjs/common';
import type {
  AuthenticationEngineResult,
  AuthenticationProviderRequest,
  AuthenticationProviderService,
  ResolvedAuthenticationProfile,
} from '../dtos/authentication-engine.dto.js';
import {
  RADIUS_AUTHENTICATOR_TOKEN,
  type IRadiusAuthenticator,
  type RadiusAuthServerOptions,
} from '../ports/radius-authenticator.interface.js';
import {
  SECRET_RESOLVER_SERVICE_TOKEN,
  type ISecretResolverService,
} from '../ports/secret-resolver.service.js';
import { radiusOptionsFromProfile } from './authentication-provider-options.js';
import { AuthenticationGroupResolverService } from './authentication-group-resolver.service.js';

@Injectable()
export class RadiusAuthenticationProviderService implements AuthenticationProviderService {
  private readonly logger = new Logger(RadiusAuthenticationProviderService.name);

  constructor(
    @Inject(RADIUS_AUTHENTICATOR_TOKEN)
    private readonly radiusAuthenticator: IRadiusAuthenticator,
    @Inject(SECRET_RESOLVER_SERVICE_TOKEN)
    private readonly secretResolver: ISecretResolverService,
    @Inject(AuthenticationGroupResolverService)
    private readonly groupResolver: AuthenticationGroupResolverService,
  ) {}

  async authenticate(
    request: AuthenticationProviderRequest,
    resolved: ResolvedAuthenticationProfile,
  ): Promise<AuthenticationEngineResult> {
    const profile = resolved.authenticationProfile;
    const radiusProfile = resolved.radiusProfile;
    if (!radiusProfile) {
      return {
        kind: 'misconfigured',
        message: `authentication profile ${profile.getId()} has no radius profile`,
        profileId: profile.getId(),
      };
    }

    const servers: RadiusAuthServerOptions[] = [];
    for (const endpoint of radiusProfile.getServers()) {
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
    const radiusRequestProfile = radiusOptionsFromProfile(radiusProfile, servers);
    const result = await this.radiusAuthenticator.authenticate({
      username: request.username,
      password: request.password,
      callingStationId: request.sourceIp ?? '127.0.0.1',
      profile: radiusRequestProfile,
    });

    if (result.kind === 'reject') {
      return {
        kind: 'reject',
        provider: 'radius',
        reason: result.reason,
        profileId: profile.getId(),
      };
    }
    if (result.kind === 'timeout') {
      return {
        kind: 'timeout',
        provider: 'radius',
        message: 'RADIUS request timed out',
        profileId: profile.getId(),
      };
    }
    if (result.kind === 'error') {
      return {
        kind: 'unavailable',
        provider: 'radius',
        message: result.message,
        profileId: profile.getId(),
      };
    }

    const groups = await this.groupResolver.resolve(
      resolved,
      request.username,
      result.groups,
    );

    this.logger.log({
      event: 'auth.radius.accepted',
      message: 'RADIUS authentication accepted',
      username: request.username,
      profileId: profile.getId(),
      groupSource: groups.source,
      groupCount: groups.groups.length,
      adminRole: result.attributes?.adminRole ?? null,
    });

    return {
      kind: 'accept',
      provider: 'radius',
      username: request.username,
      groups: groups.groups,
      groupSource: groups.source,
      externalId: groups.externalId,
      sessionTtlSeconds: profile.getSessionTtlSeconds(),
      nasIp: radiusRequestProfile.nasIp,
      calledStationId: radiusRequestProfile.calledStationId ?? radiusRequestProfile.nasIdentifier,
      profileId: profile.getId(),
      radiusAttributes: result.attributes,
    };
  }
}
