import { type AdminRoleMapping, IdentityAuthenticationProfile } from '../../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityAuthenticationSequence } from '../../../domain/entities/identity-authentication-sequence.entity.js';
import { IdentityConfiguration } from '../../../domain/entities/identity-configuration.entity.js';
import { IdentityGroup, type IdentityGroupMember } from '../../../domain/entities/identity-group.entity.js';
import { IdentitySettings } from '../../../domain/entities/identity-settings.entity.js';
import { LdapServerEndpoint } from '../../../domain/entities/ldap-server-endpoint.entity.js';
import { type LdapGroupMapping, LdapServerProfile } from '../../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerEndpoint } from '../../../domain/entities/radius-server-endpoint.entity.js';
import { RadiusServerProfile } from '../../../domain/entities/radius-server-profile.entity.js';
import type { IdentityConfigBundlePayload } from '../../../domain/value-objects/config-snapshot-payload.interface.js';
import {
  type AuthenticationSequenceRecord,
  type IdentityAuthenticationProfileRecord,
  type IdentityConfigurationRecord,
  type IdentityGroupRecord,
  IdentityConfigurationRecordSchema,
  type IdentitySettingsRecord,
  type LdapServerEndpointRecord,
  type LdapGroupMappingRecord,
  type LdapServerProfileRecord,
  type RadiusServerEndpointRecord,
  type RadiusServerProfileRecord,
} from '../schemas/identity-config.schema.js';

export class IdentityConfigJsonMapper {
  static emptyRecord(): IdentityConfigurationRecord {
    return {
      radius_server_profiles: { items: [] },
      ldap_server_profiles: { items: [] },
      authentication_profiles: { items: [] },
      authentication_sequences: { items: [] },
      identity_groups: { items: [] },
      settings: {
        portalAuthenticationProfileId: null,
        adminAuthenticationProfileId: null,
        portalListener: {
          enabled: false,
          interfaceName: null,
          zoneId: null,
          bindAddress: null,
          bindPort: 443,
        },
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
      authentication_sequences: {
        items: config.getAuthenticationSequences().map((sequence) =>
          this.sequenceToRecord(sequence),
        ),
      },
      identity_groups: {
        items: config.getIdentityGroups().map((group) =>
          this.groupToRecord(group),
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
      parsed.authentication_sequences.items.map((sequence) =>
        this.sequenceToDomain(sequence),
      ),
      parsed.identity_groups.items.map((group) =>
        this.groupToDomain(group),
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
      authentication_sequences: {
        items: config.getAuthenticationSequences(),
      },
      identity_groups: {
        items: config.getIdentityGroups(),
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
      payload.authentication_sequences?.items ?? [],
      payload.identity_groups?.items ?? [],
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
      authenticationProtocol: profile.getAuthenticationProtocol(),
      certificateProfileRef: profile.getCertificateProfileRef(),
      outerIdentity: profile.getOuterIdentity(),
      servers: profile.getServers().map((server) =>
        this.radiusEndpointToRecord(server),
      ),
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
    const servers = record.servers?.map((server) =>
      this.radiusEndpointToDomain(server),
    ) ?? [
      RadiusServerEndpoint.create(
        record.id,
        record.name,
        requireRecordValue(record.host, 'radius host'),
        requireRecordValue(record.port, 'radius port'),
        requireRecordValue(record.sharedSecretRef, 'radius sharedSecretRef'),
        1,
        record.isActive,
      ),
    ];
    const primaryServer = servers[0];

    return RadiusServerProfile.create(
      record.id,
      record.name,
      record.description,
      record.isActive,
      record.host ?? primaryServer.getHost(),
      record.port ?? primaryServer.getPort(),
      record.sharedSecretRef ?? primaryServer.getSharedSecretRef(),
      record.timeoutMs,
      record.retries,
      record.nasIp,
      record.nasIdentifier,
      record.calledStationId,
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.createdBy,
      servers,
      {
        authenticationProtocol: record.authenticationProtocol,
        certificateProfileRef: record.certificateProfileRef ?? null,
        outerIdentity: record.outerIdentity ?? null,
      },
    );
  }

  private static radiusEndpointToRecord(
    server: RadiusServerEndpoint,
  ): RadiusServerEndpointRecord {
    return {
      id: server.getId(),
      name: server.getName(),
      host: server.getHost(),
      port: server.getPort(),
      sharedSecretRef: server.getSharedSecretRef(),
      priority: server.getPriority(),
      isActive: server.getIsActive(),
    };
  }

  private static radiusEndpointToDomain(
    record: RadiusServerEndpointRecord,
  ): RadiusServerEndpoint {
    return RadiusServerEndpoint.create(
      record.id,
      record.name,
      record.host,
      record.port,
      record.sharedSecretRef,
      record.priority,
      record.isActive,
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
      serverType: profile.getServerType(),
      baseDn: profile.getBaseDn(),
      tlsMode: profile.getTlsMode(),
      verifyServerCertificate: profile.getVerifyServerCertificate(),
      certificateProfileRef: profile.getCertificateProfileRef(),
      connectTimeoutMs: profile.getConnectTimeoutMs(),
      searchTimeoutMs: profile.getSearchTimeoutMs(),
      retryIntervalSeconds: profile.getRetryIntervalSeconds(),
      bindDn: profile.getBindDn(),
      bindPasswordRef: profile.getBindPasswordRef(),
      groupMapping: this.ldapGroupMappingToRecord(profile.getGroupMapping()),
      cacheTtlSeconds: profile.getCacheTtlSeconds(),
      servers: profile.getServers().map((server) =>
        this.ldapEndpointToRecord(server),
      ),
      createdAt: profile.getCreatedAt().toISOString(),
      updatedAt: profile.getUpdatedAt().toISOString(),
      createdBy: profile.getCreatedBy(),
    };
  }

  private static ldapToDomain(record: LdapServerProfileRecord): LdapServerProfile {
    const servers = record.servers?.map((server) =>
      this.ldapEndpointToDomain(server),
    ) ?? [
      LdapServerEndpoint.create(
        record.id,
        record.name,
        requireRecordValue(record.host, 'ldap host'),
        requireRecordValue(record.port, 'ldap port'),
        1,
        record.isActive,
      ),
    ];
    const primaryServer = servers[0];
    const groupMapping = this.ldapGroupMappingToDomain(record);
    const timeoutMs = record.timeoutMs ?? record.connectTimeoutMs ?? record.searchTimeoutMs;

    return LdapServerProfile.create(
      record.id,
      record.name,
      record.description,
      record.isActive,
      record.host ?? primaryServer.getHost(),
      record.port ?? primaryServer.getPort(),
      record.tlsMode,
      record.bindDn,
      record.bindPasswordRef,
      groupMapping.userBaseDn,
      groupMapping.userFilterAttribute,
      groupMapping.groupBaseDn,
      groupMapping.groupMemberAttribute,
      groupMapping.groupNameAttribute,
      requireRecordValue(timeoutMs, 'ldap timeoutMs'),
      record.cacheTtlSeconds,
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.createdBy,
      servers,
      {
        serverType: record.serverType ?? 'active_directory',
        baseDn: record.baseDn ?? groupMapping.userBaseDn,
        verifyServerCertificate: record.verifyServerCertificate ?? false,
        certificateProfileRef: record.certificateProfileRef ?? null,
        connectTimeoutMs: record.connectTimeoutMs ?? timeoutMs,
        searchTimeoutMs: record.searchTimeoutMs ?? timeoutMs,
        retryIntervalSeconds: record.retryIntervalSeconds ?? 60,
        userNameAttribute: groupMapping.userNameAttribute,
        includeGroups: groupMapping.includeGroups,
        updateIntervalSeconds: groupMapping.updateIntervalSeconds,
      },
    );
  }

  private static ldapEndpointToRecord(
    server: LdapServerEndpoint,
  ): LdapServerEndpointRecord {
    return {
      id: server.getId(),
      name: server.getName(),
      host: server.getHost(),
      port: server.getPort(),
      priority: server.getPriority(),
      isActive: server.getIsActive(),
    };
  }

  private static ldapEndpointToDomain(
    record: LdapServerEndpointRecord,
  ): LdapServerEndpoint {
    return LdapServerEndpoint.create(
      record.id,
      record.name,
      record.host,
      record.port,
      record.priority,
      record.isActive,
    );
  }

  private static ldapGroupMappingToRecord(
    groupMapping: LdapGroupMapping,
  ): LdapGroupMappingRecord {
    return {
      userBaseDn: groupMapping.userBaseDn,
      userFilterAttribute: groupMapping.userFilterAttribute,
      userNameAttribute: groupMapping.userNameAttribute,
      groupBaseDn: groupMapping.groupBaseDn,
      groupMemberAttribute: groupMapping.groupMemberAttribute,
      groupNameAttribute: groupMapping.groupNameAttribute,
      includeGroups: [...groupMapping.includeGroups],
      updateIntervalSeconds: groupMapping.updateIntervalSeconds,
    };
  }

  private static ldapGroupMappingToDomain(
    record: LdapServerProfileRecord,
  ): LdapGroupMapping {
    if (record.groupMapping) {
      return {
        ...record.groupMapping,
        includeGroups: [...record.groupMapping.includeGroups],
      };
    }

    return {
      userBaseDn: requireRecordValue(record.userBaseDn, 'ldap userBaseDn'),
      userFilterAttribute: requireRecordValue(record.userFilterAttribute, 'ldap userFilterAttribute'),
      userNameAttribute: record.userFilterAttribute ?? 'uid',
      groupBaseDn: requireRecordValue(record.groupBaseDn, 'ldap groupBaseDn'),
      groupMemberAttribute: requireRecordValue(record.groupMemberAttribute, 'ldap groupMemberAttribute'),
      groupNameAttribute: requireRecordValue(record.groupNameAttribute, 'ldap groupNameAttribute'),
      includeGroups: [],
      updateIntervalSeconds: record.cacheTtlSeconds,
    };
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
      allowList: profile.getAllowList(),
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
      { allowList: record.allowList },
    );
  }

  private static settingsToRecord(settings: IdentitySettings): IdentitySettingsRecord {
    return {
      portalAuthenticationProfileId: settings.getPortalAuthenticationProfileId(),
      adminAuthenticationProfileId: settings.getAdminAuthenticationProfileId(),
      portalListener: {
        enabled: settings.getPortalListener().getEnabled(),
        interfaceName: settings.getPortalListener().getInterfaceName(),
        zoneId: settings.getPortalListener().getZoneId(),
        bindAddress: settings.getPortalListener().getBindAddress(),
        bindPort: settings.getPortalListener().getBindPort(),
      },
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
      record.portalListener,
    );
  }

  private static sequenceToRecord(
    sequence: IdentityAuthenticationSequence,
  ): AuthenticationSequenceRecord {
    return {
      id: sequence.getId(),
      name: sequence.getName(),
      description: sequence.getDescription(),
      isActive: sequence.getIsActive(),
      profileIds: sequence.getProfileIds(),
      exitOnReject: sequence.getExitOnReject(),
      useDomainRouting: sequence.getUseDomainRouting(),
      createdAt: sequence.getCreatedAt().toISOString(),
      updatedAt: sequence.getUpdatedAt().toISOString(),
      createdBy: sequence.getCreatedBy(),
    };
  }

  private static sequenceToDomain(
    record: AuthenticationSequenceRecord,
  ): IdentityAuthenticationSequence {
    return IdentityAuthenticationSequence.create(
      record.id,
      record.name,
      record.description,
      record.isActive,
      record.profileIds,
      record.exitOnReject,
      record.useDomainRouting,
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.createdBy,
    );
  }

  private static groupToRecord(group: IdentityGroup): IdentityGroupRecord {
    return {
      id: group.getId(),
      name: group.getName(),
      description: group.getDescription(),
      source: group.getSource(),
      externalDn: group.getExternalDn(),
      members: group.getMembers(),
      createdAt: group.getCreatedAt().toISOString(),
      updatedAt: group.getUpdatedAt().toISOString(),
      createdBy: group.getCreatedBy(),
    };
  }

  private static groupToDomain(record: IdentityGroupRecord): IdentityGroup {
    return IdentityGroup.create(
      record.id,
      record.name,
      record.description,
      record.source,
      record.externalDn,
      record.members as IdentityGroupMember[],
      new Date(record.createdAt),
      new Date(record.updatedAt),
      record.createdBy,
    );
  }
}

function requireRecordValue<T>(value: T | undefined, field: string): T {
  if (value === undefined) {
    throw new Error(`${field} is required`);
  }

  return value;
}
