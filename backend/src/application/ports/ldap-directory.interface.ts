// Port LDAP dla Issue 4 (ADR 0005). Adapter w infrastructure odpowiada za
// transport TCP, BER encoding i bind/search; warstwa wyzsza dostaje
// zdiagnostyczowany wynik (ok / not-found / disabled / error).

export type LdapGroupLookupResult =
  | { kind: 'ok'; userDn: string; groups: string[] }
  | { kind: 'not-found' }
  | { kind: 'disabled' }
  | { kind: 'error'; message: string };

export interface LdapDirectoryOptions {
  enabled: boolean;
  host: string;
  port: number;
  tlsMode: 'disabled' | 'starttls' | 'ldaps';
  bindDn: string;
  bindPassword: string;
  userBaseDn: string;
  userFilterAttribute: string;
  groupBaseDn: string;
  groupMemberAttribute: string;
  groupNameAttribute: string;
  timeoutMs: number;
}

export interface ILdapDirectory {
  isEnabled(): boolean;

  // Wykonuje bind i lookup grup uzytkownika; zwraca runtime model user -> groups.
  // Nie tworzy ani nie aktualizuje sesji identity — caller decyduje, co z tym zrobic.
  resolveGroups(
    username: string,
    options?: LdapDirectoryOptions,
  ): Promise<LdapGroupLookupResult>;
}

export const LDAP_DIRECTORY_TOKEN = Symbol('LDAP_DIRECTORY_TOKEN');
