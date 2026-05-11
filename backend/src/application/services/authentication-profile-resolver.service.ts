import { Inject, Injectable } from '@nestjs/common';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';
import type {
  AuthenticationFlow,
  AuthenticationProfileResolution,
} from '../dtos/authentication-engine.dto.js';

@Injectable()
export class AuthenticationProfileResolverService {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
  ) {}

  async resolve(flow: AuthenticationFlow): Promise<AuthenticationProfileResolution> {
    const config = await this.identityConfigRepository.find();
    const settings = config.getSettings();
    const profileId =
      flow === 'portal'
        ? settings.getPortalAuthenticationProfileId()
        : settings.getAdminAuthenticationProfileId();

    if (!profileId) {
      return flow === 'admin'
        ? { kind: 'disabled', message: 'admin authentication profile is not configured' }
        : { kind: 'misconfigured', message: 'portal authentication profile is not configured' };
    }

    const authenticationProfile = config
      .getAuthenticationProfiles()
      .find((profile) => profile.getId() === profileId);
    if (!authenticationProfile) {
      return {
        kind: 'misconfigured',
        message: `authentication profile ${profileId} does not exist`,
        profileId,
      };
    }
    if (!authenticationProfile.getIsActive()) {
      return {
        kind: 'misconfigured',
        message: `authentication profile ${profileId} is inactive`,
        profileId,
      };
    }

    const radiusProfileId =
      authenticationProfile.getProvider() === 'radius'
        ? authenticationProfile.getRadiusProfileId()
        : null;
    const ldapProfileId =
      authenticationProfile.getProvider() === 'ldap' ||
      authenticationProfile.getGroupSource() === 'ldap'
        ? authenticationProfile.getLdapProfileId()
        : null;
    const radiusProfile = radiusProfileId
      ? config
          .getRadiusServerProfiles()
          .find((profile) => profile.getId() === radiusProfileId) ?? null
      : null;
    const ldapProfile = ldapProfileId
      ? config
          .getLdapServerProfiles()
          .find((profile) => profile.getId() === ldapProfileId) ?? null
      : null;

    if (radiusProfileId && !radiusProfile) {
      return {
        kind: 'misconfigured',
        message: `radius profile ${radiusProfileId} does not exist`,
        profileId,
      };
    }
    if (ldapProfileId && !ldapProfile) {
      return {
        kind: 'misconfigured',
        message: `ldap profile ${ldapProfileId} does not exist`,
        profileId,
      };
    }
    if (radiusProfile && !radiusProfile.getIsActive()) {
      return {
        kind: 'misconfigured',
        message: `radius profile ${radiusProfile.getId()} is inactive`,
        profileId,
      };
    }
    if (ldapProfile && !ldapProfile.getIsActive()) {
      return {
        kind: 'misconfigured',
        message: `ldap profile ${ldapProfile.getId()} is inactive`,
        profileId,
      };
    }

    return {
      kind: 'resolved',
      flow,
      authenticationProfile,
      radiusProfile,
      ldapProfile,
    };
  }
}
