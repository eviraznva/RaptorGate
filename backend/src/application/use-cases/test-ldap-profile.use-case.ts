import { Inject, Injectable } from '@nestjs/common';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { IdentityProfileNotFoundException } from '../../domain/exceptions/identity-profile-not-found.exception.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type { IdentityProviderTestResponseDto } from '../dtos/identity-provider-test.dto.js';
import {
  type ILdapDirectory,
  LDAP_DIRECTORY_TOKEN,
} from '../ports/ldap-directory.interface.js';
import {
  type ISecretResolverService,
  SECRET_RESOLVER_SERVICE_TOKEN,
} from '../ports/secret-resolver.service.js';
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from '../ports/token-service.interface.js';

export interface TestLdapProfileCommand {
  accessToken: string;
  id: string;
  username: string;
}

@Injectable()
export class TestLdapProfileUseCase {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    @Inject(SECRET_RESOLVER_SERVICE_TOKEN)
    private readonly secretResolver: ISecretResolverService,
    @Inject(LDAP_DIRECTORY_TOKEN)
    private readonly ldapDirectory: ILdapDirectory,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(
    command: TestLdapProfileCommand,
  ): Promise<IdentityProviderTestResponseDto> {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const config = await this.identityConfigRepository.find();
    const profile = config
      .getLdapServerProfiles()
      .find((item) => item.getId() === command.id);
    if (!profile) throw new IdentityProfileNotFoundException('ldap', command.id);

    const bindPassword = await this.secretResolver.resolve(
      profile.getBindPasswordRef(),
    );
    const startedAt = Date.now();
    const result = await this.ldapDirectory.resolveGroups(command.username, {
      enabled: true,
      host: profile.getHost(),
      port: profile.getPort(),
      tlsMode: profile.getTlsMode(),
      bindDn: profile.getBindDn(),
      bindPassword: bindPassword.getValue(),
      userBaseDn: profile.getUserBaseDn(),
      userFilterAttribute: profile.getUserFilterAttribute(),
      groupBaseDn: profile.getGroupBaseDn(),
      groupMemberAttribute: profile.getGroupMemberAttribute(),
      groupNameAttribute: profile.getGroupNameAttribute(),
      timeoutMs: profile.getTimeoutMs(),
    });
    const latencyMs = Date.now() - startedAt;

    if (result.kind === 'ok') {
      return {
        result: 'ok',
        latencyMs,
        message: 'LDAP bind and group lookup succeeded',
        groups: result.groups,
        userDn: result.userDn,
      };
    }
    if (result.kind === 'not-found') {
      return {
        result: 'not_found',
        latencyMs,
        message: 'LDAP user was not found',
      };
    }
    if (result.kind === 'disabled') {
      return {
        result: 'disabled',
        latencyMs,
        message: 'LDAP profile is disabled',
      };
    }

    return {
      result: 'error',
      latencyMs,
      message: result.message,
    };
  }
}
