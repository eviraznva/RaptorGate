import { Inject, Injectable, Logger } from '@nestjs/common';
import type {
  AuthenticationGroupResolution,
  ResolvedAuthenticationProfile,
} from '../dtos/authentication-engine.dto.js';
import {
  LDAP_DIRECTORY_TOKEN,
  type ILdapDirectory,
} from '../ports/ldap-directory.interface.js';
import {
  SECRET_RESOLVER_SERVICE_TOKEN,
  type ISecretResolverService,
} from '../ports/secret-resolver.service.js';
import { ldapOptionsFromProfile } from './authentication-provider-options.js';

@Injectable()
export class AuthenticationGroupResolverService {
  private readonly logger = new Logger(AuthenticationGroupResolverService.name);

  constructor(
    @Inject(LDAP_DIRECTORY_TOKEN)
    private readonly ldapDirectory: ILdapDirectory,
    @Inject(SECRET_RESOLVER_SERVICE_TOKEN)
    private readonly secretResolver: ISecretResolverService,
  ) {}

  async resolve(
    resolved: ResolvedAuthenticationProfile,
    username: string,
    radiusGroups: string[],
  ): Promise<AuthenticationGroupResolution> {
    const source = resolved.authenticationProfile.getGroupSource();

    if (source === 'none') {
      return {
        groups: [],
        externalId: username,
        source,
        diagnostic: 'skipped',
      };
    }
    if (source === 'radius_vsa') {
      return {
        groups: dedup(radiusGroups),
        externalId: username,
        source,
        diagnostic: 'ok',
      };
    }

    const ldapProfile = resolved.ldapProfile;
    if (!ldapProfile) {
      return {
        groups: dedup(radiusGroups),
        externalId: username,
        source: radiusGroups.length > 0 ? 'radius_vsa' : 'none',
        diagnostic: 'error',
        error: 'ldap group source has no ldap profile',
      };
    }

    const bindPassword = await this.secretResolver.resolve(
      ldapProfile.getBindPasswordRef(),
    );
    const lookup = await this.ldapDirectory.resolveGroups(
      username,
      ldapOptionsFromProfile(ldapProfile, bindPassword.getValue()),
    );

    if (lookup.kind === 'ok') {
      return {
        groups: lookup.groups,
        externalId: lookup.userDn,
        source: 'ldap',
        diagnostic: 'ok',
      };
    }

    this.logger.warn({
      event: 'auth.identity_groups.fallback',
      message: 'LDAP group lookup failed during authentication',
      username,
      diagnostic: lookup.kind,
      error: lookup.kind === 'error' ? lookup.message : undefined,
    });

    return {
      groups: dedup(radiusGroups),
      externalId: username,
      source: radiusGroups.length > 0 ? 'radius_vsa' : 'none',
      diagnostic: lookup.kind,
      error: lookup.kind === 'error' ? lookup.message : undefined,
    };
  }
}

function dedup(values: string[]): string[] {
  const out: string[] = [];
  for (const raw of values) {
    const trimmed = raw.trim();
    if (trimmed && !out.includes(trimmed)) out.push(trimmed);
  }
  return out;
}
