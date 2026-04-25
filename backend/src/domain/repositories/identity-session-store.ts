import { IdentitySession } from '../entities/identity-session.entity.js';

// Runtime store sesji identity. Klucz: source IP klienta (zgodnie z ADR 0003).
// Jedna aktywna sesja per IP; kolejny upsert wypiera poprzednia.
export interface IIdentitySessionStore {
  runExclusiveBySourceIp<T>(sourceIp: string, action: () => Promise<T>): Promise<T>;
  upsert(session: IdentitySession): Promise<void>;
  findBySourceIp(sourceIp: string): Promise<IdentitySession | null>;
  removeBySourceIp(sourceIp: string): Promise<IdentitySession | null>;
  peekExpired(now: Date): Promise<IdentitySession[]>;
  listAll(): Promise<IdentitySession[]>;
}

export const IDENTITY_SESSION_STORE_TOKEN = Symbol(
  'IDENTITY_SESSION_STORE_TOKEN',
);
