import { Inject, Injectable, Logger } from '@nestjs/common';
import type { AuthenticationEngineAcceptResult } from '../dtos/authentication-engine.dto.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import {
  ROLE_REPOSITORY_TOKEN,
  type IRoleRepository,
} from '../../domain/repositories/role.repository.js';
import type { AdminRoleMapping } from '../../domain/entities/identity-authentication-profile.entity.js';

export type AdminAuthorizationDecision =
  | {
      kind: 'authorized';
      role: AdminRoleMapping['role'];
      matchedBy: AdminRoleMapping['matchType'];
      matchedValue: string;
    }
  | { kind: 'denied'; reason: string }
  | { kind: 'misconfigured'; reason: string };

@Injectable()
export class AdminAuthorizationService {
  private readonly logger = new Logger(AdminAuthorizationService.name);

  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
  ) {}

  async authorize(
    result: AuthenticationEngineAcceptResult,
  ): Promise<AdminAuthorizationDecision> {
    const config = await this.identityConfigRepository.find();
    const profile = config
      .getAuthenticationProfiles()
      .find((item) => item.getId() === result.profileId);
    if (!profile) {
      return {
        kind: 'misconfigured',
        reason: `authentication profile ${result.profileId} was not found`,
      };
    }

    for (const mapping of profile.getAdminRoleMappings()) {
      if (!matches(mapping, result)) continue;
      const role = await this.roleRepository.findByName(mapping.role);
      if (!role) {
        return {
          kind: 'misconfigured',
          reason: `mapped admin role ${mapping.role} was not found`,
        };
      }

      this.logger.log({
        event: 'auth.admin.authorization_succeeded',
        message: 'external admin role mapping matched',
        username: result.username,
        provider: result.provider,
        profileId: result.profileId,
        matchedBy: mapping.matchType,
        matchedValue: mapping.matchValue,
        role: mapping.role,
      });

      return {
        kind: 'authorized',
        role: mapping.role,
        matchedBy: mapping.matchType,
        matchedValue: mapping.matchValue,
      };
    }

    this.logger.warn({
      event: 'auth.admin.authorization_denied',
      message: 'external admin authentication accepted but no role mapping matched',
      username: result.username,
      provider: result.provider,
      profileId: result.profileId,
      groupSource: result.groupSource,
      groups: result.groups,
    });

    return { kind: 'denied', reason: 'admin role mapping not found' };
  }
}

function matches(
  mapping: AdminRoleMapping,
  result: AuthenticationEngineAcceptResult,
): boolean {
  if (mapping.matchType === 'username') {
    return mapping.matchValue === result.username;
  }
  if (mapping.matchType === 'ldap_group') {
    return result.groupSource === 'ldap' && result.groups.includes(mapping.matchValue);
  }
  return result.groupSource === 'radius_vsa' && result.groups.includes(mapping.matchValue);
}
