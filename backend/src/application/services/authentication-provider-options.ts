import type { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import type { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import type { LdapDirectoryOptions } from '../ports/ldap-directory.interface.js';
import type { RadiusServerOptions } from '../ports/radius-authenticator.interface.js';

export function radiusOptionsFromProfile(
  profile: RadiusServerProfile,
  secret: string,
): RadiusServerOptions {
  return {
    host: profile.getHost(),
    port: profile.getPort(),
    secret,
    timeoutMs: profile.getTimeoutMs(),
    retries: profile.getRetries(),
    nasIp: profile.getNasIp() ?? '127.0.0.1',
    nasIdentifier: profile.getNasIdentifier() ?? 'raptorgate',
    calledStationId: profile.getCalledStationId(),
  };
}

export function ldapOptionsFromProfile(
  profile: LdapServerProfile,
  bindPassword: string,
): LdapDirectoryOptions {
  return {
    enabled: profile.getIsActive(),
    host: profile.getHost(),
    port: profile.getPort(),
    tlsMode: profile.getTlsMode(),
    bindDn: profile.getBindDn(),
    bindPassword,
    userBaseDn: profile.getUserBaseDn(),
    userFilterAttribute: profile.getUserFilterAttribute(),
    groupBaseDn: profile.getGroupBaseDn(),
    groupMemberAttribute: profile.getGroupMemberAttribute(),
    groupNameAttribute: profile.getGroupNameAttribute(),
    timeoutMs: profile.getTimeoutMs(),
  };
}
