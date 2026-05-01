import type { LdapDirectoryOptions } from './ldap-directory.interface.js';

export type LdapAuthResult =
  | { kind: 'accept'; userDn: string; groups: string[] }
  | { kind: 'reject'; reason: string }
  | { kind: 'timeout'; message: string }
  | { kind: 'disabled' }
  | { kind: 'error'; message: string };

export interface LdapAuthRequest {
  username: string;
  password: string;
  options: LdapDirectoryOptions;
}

export interface ILdapAuthenticator {
  authenticate(request: LdapAuthRequest): Promise<LdapAuthResult>;
}

export const LDAP_AUTHENTICATOR_TOKEN = Symbol('LDAP_AUTHENTICATOR_TOKEN');
