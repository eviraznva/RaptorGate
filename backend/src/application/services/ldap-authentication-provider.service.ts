import { Inject, Injectable, Logger } from '@nestjs/common';
import type {
  AuthenticationEngineResult,
  AuthenticationProviderRequest,
  AuthenticationProviderService,
  ResolvedAuthenticationProfile,
} from '../dtos/authentication-engine.dto.js';
import {
  LDAP_AUTHENTICATOR_TOKEN,
  type ILdapAuthenticator,
} from '../ports/ldap-authenticator.interface.js';
import {
  SECRET_RESOLVER_SERVICE_TOKEN,
  type ISecretResolverService,
} from '../ports/secret-resolver.service.js';
import { ldapOptionsFromProfile } from './authentication-provider-options.js';

@Injectable()
export class LdapAuthenticationProviderService implements AuthenticationProviderService {
  private readonly logger = new Logger(LdapAuthenticationProviderService.name);

  constructor(
    @Inject(LDAP_AUTHENTICATOR_TOKEN)
    private readonly ldapAuthenticator: ILdapAuthenticator,
    @Inject(SECRET_RESOLVER_SERVICE_TOKEN)
    private readonly secretResolver: ISecretResolverService,
  ) {}

  async authenticate(
    request: AuthenticationProviderRequest,
    resolved: ResolvedAuthenticationProfile,
  ): Promise<AuthenticationEngineResult> {
    const profile = resolved.authenticationProfile;
    const ldapProfile = resolved.ldapProfile;
    if (!ldapProfile) {
      return {
        kind: 'misconfigured',
        message: `authentication profile ${profile.getId()} has no ldap profile`,
        profileId: profile.getId(),
      };
    }

    const bindPassword = await this.secretResolver.resolve(
      ldapProfile.getBindPasswordRef(),
    );
    const result = await this.ldapAuthenticator.authenticate({
      username: request.username,
      password: request.password,
      options: ldapOptionsFromProfile(ldapProfile, bindPassword.getValue()),
    });

    if (result.kind === 'accept') {
      this.logger.log({
        event: 'auth.ldap.accepted',
        message: 'LDAP bind authentication accepted',
        username: request.username,
        profileId: profile.getId(),
        groupCount: result.groups.length,
      });

      const groups =
        profile.getGroupSource() === 'ldap' ? result.groups : [];

      return {
        kind: 'accept',
        provider: 'ldap',
        username: request.username,
        groups,
        externalId: result.userDn,
        sessionTtlSeconds: profile.getSessionTtlSeconds(),
        nasIp: '127.0.0.1',
        calledStationId: 'ldap',
        profileId: profile.getId(),
      };
    }
    if (result.kind === 'reject') {
      return {
        kind: 'reject',
        provider: 'ldap',
        reason: result.reason,
        profileId: profile.getId(),
      };
    }
    if (result.kind === 'timeout') {
      return {
        kind: 'timeout',
        provider: 'ldap',
        message: result.message,
        profileId: profile.getId(),
      };
    }
    if (result.kind === 'disabled') {
      return {
        kind: 'misconfigured',
        message: 'LDAP profile is disabled',
        profileId: profile.getId(),
      };
    }

    return {
      kind: 'unavailable',
      provider: 'ldap',
      message: result.message,
      profileId: profile.getId(),
    };
  }
}
