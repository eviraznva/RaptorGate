import { Inject, Injectable, Logger } from '@nestjs/common';
import type {
  AuthenticationEngineRequest,
  AuthenticationEngineResult,
  AuthenticationProviderService,
} from '../dtos/authentication-engine.dto.js';
import { AuthenticationMisconfiguredException } from '../../domain/exceptions/authentication-misconfigured.exception.js';
import { AuthenticationProfileResolverService } from './authentication-profile-resolver.service.js';
import { LdapAuthenticationProviderService } from './ldap-authentication-provider.service.js';
import { LocalAuthenticationProviderService } from './local-authentication-provider.service.js';
import { RadiusAuthenticationProviderService } from './radius-authentication-provider.service.js';

@Injectable()
export class AuthenticationEngineService {
  private readonly logger = new Logger(AuthenticationEngineService.name);

  constructor(
    @Inject(AuthenticationProfileResolverService)
    private readonly resolver: AuthenticationProfileResolverService,
    @Inject(RadiusAuthenticationProviderService)
    private readonly radiusProvider: AuthenticationProviderService,
    @Inject(LdapAuthenticationProviderService)
    private readonly ldapProvider: AuthenticationProviderService,
    @Inject(LocalAuthenticationProviderService)
    private readonly localProvider: AuthenticationProviderService,
  ) {}

  async authenticate(
    request: AuthenticationEngineRequest,
  ): Promise<AuthenticationEngineResult> {
    const resolved = await this.resolver.resolve(request.flow);
    if (resolved.kind !== 'resolved') return resolved;

    const provider = resolved.authenticationProfile.getProvider();
    const service = this.providerFor(provider);
    const result = await service.authenticate(
      {
        username: request.username,
        password: request.password,
        sourceIp: request.sourceIp,
      },
      resolved,
    );

    this.logger.log({
      event: 'auth.engine.result',
      message: 'authentication engine completed',
      flow: request.flow,
      provider,
      username: request.username,
      result: result.kind,
      profileId: resolved.authenticationProfile.getId(),
    });

    return result;
  }

  private providerFor(provider: string): AuthenticationProviderService {
    if (provider === 'radius') return this.radiusProvider;
    if (provider === 'ldap') return this.ldapProvider;
    if (provider === 'local') return this.localProvider;
    throw new AuthenticationMisconfiguredException(
      `unknown authentication provider ${provider}`,
    );
  }
}
