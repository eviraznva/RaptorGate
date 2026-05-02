export type IdentityProvider = "radius" | "ldap" | "local";
export type IdentityGroupSource = "none" | "ldap" | "radius_vsa";
export type AdminRoleMappingMatchType = "username" | "ldap_group" | "radius_vsa";
export type AdminRole = "super_admin" | "admin" | "operator" | "viewer";
export type LdapTlsMode = "disabled" | "starttls" | "ldaps";

export type RadiusServerProfile = {
  id: string;
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
  createdAt: string;
  updatedAt: string;
  createdBy: string;
};

export type LdapServerProfile = {
  id: string;
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
  createdAt: string;
  updatedAt: string;
  createdBy: string;
};

export type AdminRoleMapping = {
  matchType: AdminRoleMappingMatchType;
  matchValue: string;
  role: AdminRole;
};

export type IdentityAuthenticationProfile = {
  id: string;
  name: string;
  description: string | null;
  isActive: boolean;
  provider: IdentityProvider;
  radiusProfileId: string | null;
  ldapProfileId: string | null;
  groupSource: IdentityGroupSource;
  sessionTtlSeconds: number;
  adminRoleMappings: AdminRoleMapping[];
  createdAt: string;
  updatedAt: string;
  createdBy: string;
};

export type IdentitySettings = {
  portalAuthenticationProfileId: string | null;
  adminAuthenticationProfileId: string | null;
  updatedAt: string | null;
  updatedBy: string | null;
};

export type IdentityConfig = {
  radiusServerProfiles: RadiusServerProfile[];
  ldapServerProfiles: LdapServerProfile[];
  authenticationProfiles: IdentityAuthenticationProfile[];
  settings: IdentitySettings;
};

export type IdentityProviderTestResult = {
  result: "accept" | "reject" | "timeout" | "error" | "ok";
  latencyMs: number;
  message: string;
  groups?: string[];
  userDn?: string;
};
