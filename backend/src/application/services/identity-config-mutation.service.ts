import { Injectable } from '@nestjs/common';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import { IdentityConfigIsInvalidException } from '../../domain/exceptions/identity-config-is-invalid.exception.js';
import { IdentityProfileInUseException } from '../../domain/exceptions/identity-profile-in-use.exception.js';
import { IdentityProfileNotFoundException } from '../../domain/exceptions/identity-profile-not-found.exception.js';

@Injectable()
export class IdentityConfigMutationService {
  addRadiusProfile(
    config: IdentityConfiguration,
    profile: RadiusServerProfile,
  ): IdentityConfiguration {
    return IdentityConfiguration.create(
      [...config.getRadiusServerProfiles(), profile],
      config.getLdapServerProfiles(),
      config.getAuthenticationProfiles(),
      config.getSettings(),
    );
  }

  replaceRadiusProfile(
    config: IdentityConfiguration,
    profile: RadiusServerProfile,
  ): IdentityConfiguration {
    const profiles = config.getRadiusServerProfiles();
    const index = profiles.findIndex((item) => item.getId() === profile.getId());
    if (index < 0) throw new IdentityProfileNotFoundException('radius', profile.getId());

    profiles[index] = profile;

    return IdentityConfiguration.create(
      profiles,
      config.getLdapServerProfiles(),
      config.getAuthenticationProfiles(),
      config.getSettings(),
    );
  }

  deleteRadiusProfile(
    config: IdentityConfiguration,
    profileId: string,
  ): IdentityConfiguration {
    const profiles = config.getRadiusServerProfiles();
    if (!profiles.some((profile) => profile.getId() === profileId)) {
      throw new IdentityProfileNotFoundException('radius', profileId);
    }

    const usedBy = config
      .getAuthenticationProfiles()
      .find((profile) => profile.getRadiusProfileId() === profileId);
    if (usedBy) {
      throw new IdentityProfileInUseException(
        'radius',
        profileId,
        `authentication profile "${usedBy.getId()}"`,
      );
    }

    return IdentityConfiguration.create(
      profiles.filter((profile) => profile.getId() !== profileId),
      config.getLdapServerProfiles(),
      config.getAuthenticationProfiles(),
      config.getSettings(),
    );
  }

  addLdapProfile(
    config: IdentityConfiguration,
    profile: LdapServerProfile,
  ): IdentityConfiguration {
    return IdentityConfiguration.create(
      config.getRadiusServerProfiles(),
      [...config.getLdapServerProfiles(), profile],
      config.getAuthenticationProfiles(),
      config.getSettings(),
    );
  }

  replaceLdapProfile(
    config: IdentityConfiguration,
    profile: LdapServerProfile,
  ): IdentityConfiguration {
    const profiles = config.getLdapServerProfiles();
    const index = profiles.findIndex((item) => item.getId() === profile.getId());
    if (index < 0) throw new IdentityProfileNotFoundException('ldap', profile.getId());

    profiles[index] = profile;

    return IdentityConfiguration.create(
      config.getRadiusServerProfiles(),
      profiles,
      config.getAuthenticationProfiles(),
      config.getSettings(),
    );
  }

  deleteLdapProfile(
    config: IdentityConfiguration,
    profileId: string,
  ): IdentityConfiguration {
    const profiles = config.getLdapServerProfiles();
    if (!profiles.some((profile) => profile.getId() === profileId)) {
      throw new IdentityProfileNotFoundException('ldap', profileId);
    }

    const usedBy = config
      .getAuthenticationProfiles()
      .find((profile) => profile.getLdapProfileId() === profileId);
    if (usedBy) {
      throw new IdentityProfileInUseException(
        'ldap',
        profileId,
        `authentication profile "${usedBy.getId()}"`,
      );
    }

    return IdentityConfiguration.create(
      config.getRadiusServerProfiles(),
      profiles.filter((profile) => profile.getId() !== profileId),
      config.getAuthenticationProfiles(),
      config.getSettings(),
    );
  }

  addAuthenticationProfile(
    config: IdentityConfiguration,
    profile: IdentityAuthenticationProfile,
  ): IdentityConfiguration {
    this.assertAuthenticationProfileReferences(config, profile);

    return IdentityConfiguration.create(
      config.getRadiusServerProfiles(),
      config.getLdapServerProfiles(),
      [...config.getAuthenticationProfiles(), profile],
      config.getSettings(),
    );
  }

  replaceAuthenticationProfile(
    config: IdentityConfiguration,
    profile: IdentityAuthenticationProfile,
  ): IdentityConfiguration {
    const profiles = config.getAuthenticationProfiles();
    const index = profiles.findIndex((item) => item.getId() === profile.getId());
    if (index < 0) {
      throw new IdentityProfileNotFoundException('authentication', profile.getId());
    }
    this.assertAuthenticationProfileReferences(config, profile);

    profiles[index] = profile;

    return IdentityConfiguration.create(
      config.getRadiusServerProfiles(),
      config.getLdapServerProfiles(),
      profiles,
      config.getSettings(),
    );
  }

  deleteAuthenticationProfile(
    config: IdentityConfiguration,
    profileId: string,
  ): IdentityConfiguration {
    const profiles = config.getAuthenticationProfiles();
    if (!profiles.some((profile) => profile.getId() === profileId)) {
      throw new IdentityProfileNotFoundException('authentication', profileId);
    }

    const settings = config.getSettings();
    if (settings.getPortalAuthenticationProfileId() === profileId) {
      throw new IdentityProfileInUseException(
        'authentication',
        profileId,
        'identity settings portalAuthenticationProfileId',
      );
    }

    if (settings.getAdminAuthenticationProfileId() === profileId) {
      throw new IdentityProfileInUseException(
        'authentication',
        profileId,
        'identity settings adminAuthenticationProfileId',
      );
    }

    return IdentityConfiguration.create(
      config.getRadiusServerProfiles(),
      config.getLdapServerProfiles(),
      profiles.filter((profile) => profile.getId() !== profileId),
      settings,
    );
  }

  replaceSettings(
    config: IdentityConfiguration,
    settings: IdentitySettings,
  ): IdentityConfiguration {
    this.assertAuthenticationProfileExists(
      config,
      settings.getPortalAuthenticationProfileId(),
    );
    this.assertAuthenticationProfileExists(
      config,
      settings.getAdminAuthenticationProfileId(),
    );
    this.assertAdminAuthenticationProfileIsExternal(
      config,
      settings.getAdminAuthenticationProfileId(),
    );

    return IdentityConfiguration.create(
      config.getRadiusServerProfiles(),
      config.getLdapServerProfiles(),
      config.getAuthenticationProfiles(),
      settings,
    );
  }

  private assertAuthenticationProfileReferences(
    config: IdentityConfiguration,
    profile: IdentityAuthenticationProfile,
  ): void {
    const radiusProfileId = profile.getRadiusProfileId();
    if (
      radiusProfileId &&
      !config
        .getRadiusServerProfiles()
        .some((item) => item.getId() === radiusProfileId)
    ) {
      throw new IdentityProfileNotFoundException('radius', radiusProfileId);
    }

    const ldapProfileId = profile.getLdapProfileId();
    if (
      ldapProfileId &&
      !config.getLdapServerProfiles().some((item) => item.getId() === ldapProfileId)
    ) {
      throw new IdentityProfileNotFoundException('ldap', ldapProfileId);
    }
  }

  private assertAuthenticationProfileExists(
    config: IdentityConfiguration,
    profileId: string | null,
  ): void {
    if (!profileId) return;

    if (
      !config
        .getAuthenticationProfiles()
        .some((profile) => profile.getId() === profileId)
    ) {
      throw new IdentityProfileNotFoundException('authentication', profileId);
    }
  }

  private assertAdminAuthenticationProfileIsExternal(
    config: IdentityConfiguration,
    profileId: string | null,
  ): void {
    if (!profileId) return;

    const profile = config
      .getAuthenticationProfiles()
      .find((item) => item.getId() === profileId);
    if (profile?.getProvider() === 'local') {
      throw new IdentityConfigIsInvalidException('admin authentication profile cannot use local provider');
    }
  }
}
