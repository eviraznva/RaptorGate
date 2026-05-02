import { type AdminRoleMapping, IdentityAuthenticationProfile } from '../../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../../../domain/entities/radius-server-profile.entity.js';
import type { IdentityConfigBundlePayload } from '../../../domain/value-objects/config-snapshot-payload.interface.js';
import {
  type IdentityAuthenticationProfileRecord,
  type IdentityConfigurationRecord,
  IdentityConfigurationRecordSchema,
  type IdentitySettingsRecord,
  type LdapServerProfileRecord,
  type RadiusServerProfileRecord,
} from '../schemas/identity-config.schema.js';

export class IdentityConfigJsonMapper {
  static emptyRecord(): IdentityConfigurationRecord {
    return {
      radius_server_profiles: { items: [] },
      ldap_server_profiles: { items: [] },
      authentication_profiles: { items: [] },
      settings: {
        portalAuthenticationProfileId: null,
        adminAuthenticationProfileId: null,
        updatedAt: null,
        updatedBy: null,
      },
    };
  }

  static toRecord(config: IdentityConfiguration): IdentityConfigurationRecord {
    return {
      radius_server_profiles: {
        items: config.getRadiusServerProfiles().map((profile) =>
          this.radiusToRecord(profile),
        ),
      },
      ldap_server_profiles: {
        items: config.getLdapServerProfiles().map((profile) =>
          this.ldapToRecord(profile),
        ),
      },
      authentication_profiles: {
        items: config.getAuthenticationProfiles().map((profile) =>
          this.authToRecord(profile),
        ),
      },
      settings: this.settingsToRecord(config.getSettings()),
    };
  }

  static toDomain(record: unknown): IdentityConfiguration {
    const parsed = IdentityConfigurationRecordSchema.parse(record);

    return IdentityConfiguration.create(
      parsed.radius_server_profiles.items.map((profile) =>
        this.radiusToDomain(profile),
      ),
      parsed.ldap_server_profiles.items.map((profile) =>
        this.ldapToDomain(profile),
      ),
      parsed.authentication_profiles.items.map((profile) =>
        this.authToDomain(profile),
      ),
      this.settingsToDomain(parsed.settings),
    );
  }

  static toPayload(config: IdentityConfiguration): IdentityConfigBundlePayload {
    return {
      radius_server_profiles: {
        items: config.getRadiusServerProfiles(),
      },
      ldap_server_profiles: {
        items: config.getLdapServerProfiles(),
      },
      authentication_profiles: {
        items: config.getAuthenticationProfiles(),
      },
      settings: config.getSettings(),
    };
  }

  static payloadToRecord(
    payload: IdentityConfigBundlePayload,
  ): IdentityConfigurationRecord {
    return this.toRecord(this.payloadToDomain(payload));
  }

  static payloadToDomain(
    payload: IdentityConfigBundlePayload,
  ): IdentityConfiguration {
    return IdentityConfiguration.create(
      payload.radius_server_profiles.items,
      payload.ldap_server_profiles.items,
      payload.authentication_profiles.items,
      payload.settings,
    );
  }

  static recordToPayload(record: unknown): IdentityConfigBundlePayload {
    return this.toPayload(this.toDomain(record ?? this.emptyRecord()));
  }

  private static radiusToRecord(
    profile: RadiusServerProfile,
  ): RadiusServerProfileRecord {
    return {
      id: profile.getId(),
      name: profile.getName(),
      description: profile.getDescription(),
      isActive: profile.getIsActive(),
      host: profile.getHost(),
      port: profile.getPort(),
      sharedSecretRef: profile.getSharedSecretRef(),
      timeoutMs: profile.getTimeoutMs(),
      retries: profile.getRetries(),
      nasIp: profile.getNasIp(),
      nasIdentifier: profile.getNasIdentifier(),
      calledStationId: profile.getCalledStationId(),
      createdAt: profile.getCreatedAt().toISOString(),
      updatedAt: profile.getUpdatedAt().toISOString(),
      createdBy: profile.getCreatedBy(),
    };
  }

  private static radiusToDomain(
    record: RadiusServerProfileRecord,
  ): RadiusServerProfile {
    return RadiusServerProfile.create(
      record.id,
      record.name,
      record.description,
      record.isActive,
      record.host,
      record.port,
      record.sharedSecretRef,
      record.timeoutMs,
      record.retries,
      record.nasIp,
      record.nasIdentifier,
      record.calledStationId,
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.createdBy,
    );
  }

  private static ldapToRecord(
    profile: LdapServerProfile,
  ): LdapServerProfileRecord {
    return {
      id: profile.getId(),
      name: profile.getName(),
      description: profile.getDescription(),
      isActive: profile.getIsActive(),
      host: profile.getHost(),
      port: profile.getPort(),
      tlsMode: profile.getTlsMode(),
      bindDn: profile.getBindDn(),
      bindPasswordRef: profile.getBindPasswordRef(),
      userBaseDn: profile.getUserBaseDn(),
      userFilterAttribute: profile.getUserFilterAttribute(),
      groupBaseDn: profile.getGroupBaseDn(),
      groupMemberAttribute: profile.getGroupMemberAttribute(),
      groupNameAttribute: profile.getGroupNameAttribute(),
      timeoutMs: profile.getTimeoutMs(),
      cacheTtlSeconds: profile.getCacheTtlSeconds(),
      createdAt: profile.getCreatedAt().toISOString(),
      updatedAt: profile.getUpdatedAt().toISOString(),
      createdBy: profile.getCreatedBy(),
    };
  }

  private static ldapToDomain(record: LdapServerProfileRecord): LdapServerProfile {
    return LdapServerProfile.create(
      record.id,
      record.name,
      record.description,
      record.isActive,
      record.host,
      record.port,
      record.tlsMode,
      record.bindDn,
      record.bindPasswordRef,
      record.userBaseDn,
      record.userFilterAttribute,
      record.groupBaseDn,
      record.groupMemberAttribute,
      record.groupNameAttribute,
      record.timeoutMs,
      record.cacheTtlSeconds,
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.createdBy,
    );
  }

  private static authToRecord(
    profile: IdentityAuthenticationProfile,
  ): IdentityAuthenticationProfileRecord {
    return {
      id: profile.getId(),
      name: profile.getName(),
      description: profile.getDescription(),
      isActive: profile.getIsActive(),
      provider: profile.getProvider(),
      radiusProfileId: profile.getRadiusProfileId(),
      ldapProfileId: profile.getLdapProfileId(),
      groupSource: profile.getGroupSource(),
      sessionTtlSeconds: profile.getSessionTtlSeconds(),
      adminRoleMappings: profile.getAdminRoleMappings(),
      createdAt: profile.getCreatedAt().toISOString(),
      updatedAt: profile.getUpdatedAt().toISOString(),
      createdBy: profile.getCreatedBy(),
    };
  }

  private static authToDomain(
    record: IdentityAuthenticationProfileRecord,
  ): IdentityAuthenticationProfile {
    return IdentityAuthenticationProfile.create(
      record.id,
      record.name,
      record.description,
      record.isActive,
      record.provider,
      record.radiusProfileId,
      record.ldapProfileId,
      record.groupSource,
      record.sessionTtlSeconds,
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.createdBy,
      record.adminRoleMappings as AdminRoleMapping[],
    );
  }

  private static settingsToRecord(settings: IdentitySettings): IdentitySettingsRecord {
    return {
      portalAuthenticationProfileId: settings.getPortalAuthenticationProfileId(),
      adminAuthenticationProfileId: settings.getAdminAuthenticationProfileId(),
      updatedAt: settings.getUpdatedAt()?.toISOString() ?? null,
      updatedBy: settings.getUpdatedBy(),
    };
  }

  private static settingsToDomain(record: IdentitySettingsRecord): IdentitySettings {
    return IdentitySettings.create(
      record.portalAuthenticationProfileId,
      record.adminAuthenticationProfileId,
      record.updatedAt ? new Date(record.updatedAt) : null,
      record.updatedBy,
    );
  }
}
