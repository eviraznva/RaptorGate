import { AdminAuthSession } from '../../../domain/entities/admin-auth-session.entity.js';
import type { AdminAuthSessionRecord } from '../schemas/admin-auth-sessions.schema.js';

export class AdminAuthSessionJsonMapper {
  static toRecord(session: AdminAuthSession): AdminAuthSessionRecord {
    return {
      id: session.getId(),
      username: session.getUsername(),
      provider: session.getProvider(),
      authProfileId: session.getAuthProfileId(),
      externalId: session.getExternalId(),
      roles: session.getRoles(),
      refreshTokenHash: session.getRefreshTokenHash(),
      refreshTokenExpiry: session.getRefreshTokenExpiry().toISOString(),
      createdAt: session.getCreatedAt().toISOString(),
      lastSeenAt: session.getLastSeenAt().toISOString(),
      revokedAt: session.getRevokedAt()?.toISOString() ?? null,
    };
  }

  static toDomain(record: AdminAuthSessionRecord): AdminAuthSession {
    return AdminAuthSession.create(
      record.id,
      record.username,
      record.provider,
      record.authProfileId,
      record.externalId,
      record.roles,
      record.refreshTokenHash,
      new Date(record.refreshTokenExpiry),
      new Date(record.createdAt),
      new Date(record.lastSeenAt),
      record.revokedAt ? new Date(record.revokedAt) : null,
    );
  }
}
