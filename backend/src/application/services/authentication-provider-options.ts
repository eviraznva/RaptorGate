import type { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import type { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import type { LdapDirectoryOptions } from '../ports/ldap-directory.interface.js';
import type { RadiusAuthProfileOptions, RadiusAuthServerOptions } from '../ports/radius-authenticator.interface.js';

export function radiusOptionsFromProfile(
  profile: RadiusServerProfile,
  servers: RadiusAuthServerOptions[],
): RadiusAuthProfileOptions {
  return {
    authenticationProtocol: profile.getAuthenticationProtocol(),
    timeoutMs: profile.getTimeoutMs(),
    retries: profile.getRetries(),
    nasIp: profile.getNasIp() ?? '127.0.0.1',
    nasIdentifier: profile.getNasIdentifier() ?? 'raptorgate',
    calledStationId: profile.getCalledStationId(),
    servers,
  };
}

export function ldapOptionsFromProfile(
  profile: LdapServerProfile,
  bindPassword: string,
): LdapDirectoryOptions {
  const server = profile
    .getServers()
    .filter((item) => item.getIsActive())
    .sort((a, b) => a.getPriority() - b.getPriority())[0];
  const groupMapping = profile.getGroupMapping();

  return {
    enabled: profile.getIsActive(),
    host: server?.getHost() ?? profile.getHost(),
    port: server?.getPort() ?? profile.getPort(),
    tlsMode: profile.getTlsMode(),
    verifyServerCertificate: profile.getVerifyServerCertificate(),
    servername: server?.getHost() ?? profile.getHost(),
    bindDn: profile.getBindDn(),
    bindPassword,
    userBaseDn: groupMapping.userBaseDn,
    userFilterAttribute: groupMapping.userFilterAttribute,
    userNameAttribute: groupMapping.userNameAttribute,
    groupBaseDn: groupMapping.groupBaseDn,
    groupMemberAttribute: groupMapping.groupMemberAttribute,
    groupNameAttribute: groupMapping.groupNameAttribute,
    includeGroups: groupMapping.includeGroups,
    connectTimeoutMs: profile.getConnectTimeoutMs(),
    searchTimeoutMs: profile.getSearchTimeoutMs(),
    timeoutMs: profile.getTimeoutMs(),
  };
}
