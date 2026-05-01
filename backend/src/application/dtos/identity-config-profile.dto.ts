import type {
  IdentityAuthenticationProvider,
  IdentityGroupSource,
} from '../../domain/entities/identity-authentication-profile.entity.js';
import type { LdapTlsMode } from '../../domain/entities/ldap-server-profile.entity.js';

export interface RadiusProfileInputDto {
  name: string;
  description: string | null;
  isActive: boolean;
  host: string;
  port: number;
  sharedSecretRef: string;
  timeoutMs: number;
  retries: number;
  nasIp: string | null;
  nasIdentifier: string | null;
  calledStationId: string | null;
}

export interface LdapProfileInputDto {
  name: string;
  description: string | null;
  isActive: boolean;
  host: string;
  port: number;
  tlsMode: LdapTlsMode;
  bindDn: string;
  bindPasswordRef: string;
  userBaseDn: string;
  userFilterAttribute: string;
  groupBaseDn: string;
  groupMemberAttribute: string;
  groupNameAttribute: string;
  timeoutMs: number;
  cacheTtlSeconds: number;
}

export interface AuthenticationProfileInputDto {
  name: string;
  description: string | null;
  isActive: boolean;
  provider: IdentityAuthenticationProvider;
  radiusProfileId: string | null;
  ldapProfileId: string | null;
  groupSource: IdentityGroupSource;
  sessionTtlSeconds: number;
}

export interface IdentitySettingsInputDto {
  portalAuthenticationProfileId?: string | null;
  adminAuthenticationProfileId?: string | null;
}
