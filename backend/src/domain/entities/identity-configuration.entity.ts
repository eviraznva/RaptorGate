import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { IdentityAuthenticationSequence } from './identity-authentication-sequence.entity.js';
import { IdentityAuthenticationProfile } from './identity-authentication-profile.entity.js';
import { IdentityGroup } from './identity-group.entity.js';
import { type IdentityAuthenticationTarget, IdentitySettings } from './identity-settings.entity.js';
import { LdapServerProfile } from './ldap-server-profile.entity.js';
import { RadiusServerProfile } from './radius-server-profile.entity.js';

export class IdentityConfiguration {
  private constructor(
    private readonly radiusServerProfiles: RadiusServerProfile[],
    private readonly ldapServerProfiles: LdapServerProfile[],
    private readonly authenticationProfiles: IdentityAuthenticationProfile[],
    private readonly authenticationSequences: IdentityAuthenticationSequence[],
    private readonly identityGroups: IdentityGroup[],
    private readonly settings: IdentitySettings,
  ) {}

  public static empty(): IdentityConfiguration {
    return IdentityConfiguration.create(
      [],
      [],
      [],
      [],
      [],
      IdentitySettings.create(null, null, null, null),
    );
  }

  public static create(
    radiusServerProfiles: RadiusServerProfile[],
    ldapServerProfiles: LdapServerProfile[],
    authenticationProfiles: IdentityAuthenticationProfile[],
    settings: IdentitySettings,
  ): IdentityConfiguration;

  public static create(
    radiusServerProfiles: RadiusServerProfile[],
    ldapServerProfiles: LdapServerProfile[],
    authenticationProfiles: IdentityAuthenticationProfile[],
    authenticationSequences: IdentityAuthenticationSequence[],
    identityGroups: IdentityGroup[],
    settings: IdentitySettings,
  ): IdentityConfiguration;

  public static create(
    radiusServerProfiles: RadiusServerProfile[],
    ldapServerProfiles: LdapServerProfile[],
    authenticationProfiles: IdentityAuthenticationProfile[],
    authenticationSequencesOrSettings: IdentityAuthenticationSequence[] | IdentitySettings,
    identityGroups: IdentityGroup[] = [],
    settingsInput: IdentitySettings | null = null,
  ): IdentityConfiguration {
    const authenticationSequences =
      authenticationSequencesOrSettings instanceof IdentitySettings
        ? []
        : authenticationSequencesOrSettings;
    const settings =
      authenticationSequencesOrSettings instanceof IdentitySettings
        ? authenticationSequencesOrSettings
        : settingsInput;

    if (!settings) {
      throw new IdentityConfigIsInvalidException('identity settings are required');
    }

    assertUnique(radiusServerProfiles.map((p) => p.getId()), 'radius profile id');
    assertUnique(radiusServerProfiles.map((p) => p.getName()), 'radius profile name');
    assertUnique(ldapServerProfiles.map((p) => p.getId()), 'ldap profile id');
    assertUnique(ldapServerProfiles.map((p) => p.getName()), 'ldap profile name');
    assertUnique(authenticationProfiles.map((p) => p.getId()), 'authentication profile id');
    assertUnique(authenticationProfiles.map((p) => p.getName()), 'authentication profile name');
    assertUnique(authenticationSequences.map((p) => p.getId()), 'authentication sequence id');
    assertUnique(authenticationSequences.map((p) => p.getName()), 'authentication sequence name');
    assertUnique(identityGroups.map((p) => p.getId()), 'identity group id');
    assertUnique(identityGroups.map((p) => p.getName()), 'identity group name');

    const radiusIds = new Set(radiusServerProfiles.map((p) => p.getId()));
    const ldapIds = new Set(ldapServerProfiles.map((p) => p.getId()));

    for (const profile of authenticationProfiles) {
      const radiusProfileId = profile.getRadiusProfileId();
      const ldapProfileId = profile.getLdapProfileId();

      if (radiusProfileId && !radiusIds.has(radiusProfileId)) {
        throw new IdentityConfigIsInvalidException(`authentication profile ${profile.getId()} references missing radius profile ${radiusProfileId}`);
      }

      if (ldapProfileId && !ldapIds.has(ldapProfileId)) {
        throw new IdentityConfigIsInvalidException(`authentication profile ${profile.getId()} references missing ldap profile ${ldapProfileId}`);
      }
    }

    const authIds = new Set(authenticationProfiles.map((p) => p.getId()));
    const sequenceIds = new Set(authenticationSequences.map((p) => p.getId()));
    for (const sequence of authenticationSequences) {
      for (const profileId of sequence.getProfileIds()) {
        if (!authIds.has(profileId)) {
          throw new IdentityConfigIsInvalidException(`authentication sequence ${sequence.getId()} references missing authentication profile ${profileId}`);
        }
      }
    }
    assertSettingsTarget(settings.getPortalAuthenticationTarget(), authIds, sequenceIds, 'portalAuthenticationTarget');
    assertSettingsTarget(settings.getAdminAuthenticationTarget(), authIds, sequenceIds, 'adminAuthenticationTarget');

    return new IdentityConfiguration(
      [...radiusServerProfiles],
      [...ldapServerProfiles],
      [...authenticationProfiles],
      [...authenticationSequences],
      [...identityGroups],
      settings,
    );
  }

  public getRadiusServerProfiles(): RadiusServerProfile[] {
    return [...this.radiusServerProfiles];
  }

  public getLdapServerProfiles(): LdapServerProfile[] {
    return [...this.ldapServerProfiles];
  }

  public getAuthenticationProfiles(): IdentityAuthenticationProfile[] {
    return [...this.authenticationProfiles];
  }

  public getAuthenticationSequences(): IdentityAuthenticationSequence[] {
    return [...this.authenticationSequences];
  }

  public getIdentityGroups(): IdentityGroup[] {
    return [...this.identityGroups];
  }

  public getSettings(): IdentitySettings {
    return this.settings;
  }
}

function assertUnique(values: string[], field: string): void {
  const seen = new Set<string>();

  for (const value of values) {
    if (seen.has(value)) {
      throw new IdentityConfigIsInvalidException(`duplicate ${field}: ${value}`);
    }
    seen.add(value);
  }
}

function assertSettingsTarget(
  target: IdentityAuthenticationTarget | null,
  authIds: Set<string>,
  sequenceIds: Set<string>,
  field: string,
): void {
  if (!target) return;
  if (target.kind === 'profile' && !authIds.has(target.id)) {
    throw new IdentityConfigIsInvalidException(`${field} references missing authentication profile ${target.id}`);
  }
  if (target.kind === 'sequence' && !sequenceIds.has(target.id)) {
    throw new IdentityConfigIsInvalidException(`${field} references missing authentication sequence ${target.id}`);
  }
}
