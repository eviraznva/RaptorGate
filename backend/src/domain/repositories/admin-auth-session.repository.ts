import type { AdminAuthSession } from '../entities/admin-auth-session.entity.js';

export interface IAdminAuthSessionRepository {
  findById(id: string): Promise<AdminAuthSession | null>;
  save(session: AdminAuthSession): Promise<void>;
  revoke(id: string, revokedAt: Date): Promise<void>;
}

export const ADMIN_AUTH_SESSION_REPOSITORY_TOKEN = Symbol(
  'ADMIN_AUTH_SESSION_REPOSITORY_TOKEN',
);
