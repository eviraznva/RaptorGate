import type { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import type { IdentityConfigResponseDto } from '../dtos/identity-config-profile-response.dto.js';

export class IdentityConfigResponseMapper {
  static toResponse(config: IdentityConfiguration): IdentityConfigResponseDto {
    return {
      radiusServerProfiles: config.getRadiusServerProfiles().map((profile) => ({
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
        createdAt: profile.getCreatedAt(),
        updatedAt: profile.getUpdatedAt(),
        createdBy: profile.getCreatedBy(),
      })),
      ldapServerProfiles: config.getLdapServerProfiles().map((profile) => ({
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
        createdAt: profile.getCreatedAt(),
        updatedAt: profile.getUpdatedAt(),
        createdBy: profile.getCreatedBy(),
      })),
      authenticationProfiles: config.getAuthenticationProfiles().map((profile) => ({
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
        createdAt: profile.getCreatedAt(),
        updatedAt: profile.getUpdatedAt(),
        createdBy: profile.getCreatedBy(),
      })),
      settings: {
        portalAuthenticationProfileId:
          config.getSettings().getPortalAuthenticationProfileId(),
        adminAuthenticationProfileId:
          config.getSettings().getAdminAuthenticationProfileId(),
        portalListener: {
          enabled: config.getSettings().getPortalListener().getEnabled(),
          interfaceName: config.getSettings().getPortalListener().getInterfaceName(),
          zoneId: config.getSettings().getPortalListener().getZoneId(),
          bindAddress: config.getSettings().getPortalListener().getBindAddress(),
          bindPort: config.getSettings().getPortalListener().getBindPort(),
        },
        updatedAt: config.getSettings().getUpdatedAt(),
        updatedBy: config.getSettings().getUpdatedBy(),
      },
    };
  }
}
