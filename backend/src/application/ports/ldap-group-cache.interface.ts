// Cache user -> groups niezalezny od sesji identity (Issue 4, ADR 0005).
// Trzymany w pamieci backendu jak runtime sesje, ale z osobnym TTL — zmiana
// grup w LDAP propaguje sie do polityk bez relogowania uzytkownika.

export interface ILdapGroupCache {
  get(username: string): string[] | null;
  set(username: string, groups: string[]): void;
  invalidate(username: string): void;
}

export const LDAP_GROUP_CACHE_TOKEN = Symbol('LDAP_GROUP_CACHE_TOKEN');
