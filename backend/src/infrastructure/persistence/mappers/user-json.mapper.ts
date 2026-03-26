import { User } from '../../../domain/entities/user.entity.js';
import { UserRecord } from '../schemas/users.schema.js';

export class UserJsonMapper {
  static toDomain(record: UserRecord): User {
    return User.create(
      record.id,
      record.username,
      record.passwordHash,
      record.refreshToken,
      record.refreshTokenExpiry ? new Date(record.refreshTokenExpiry) : null,
      new Date(record.createdAt),
      new Date(record.updatedAt),
      [],
    );
  }

  static toRecord(user: User): UserRecord {
    return {
      id: user.getId(),
      username: user.getUsername(),
      passwordHash: user.getPasswordHash(),
      refreshToken: user.getRefreshToken(),
      refreshTokenExpiry: user.getRefreshTokenExpiry()?.toISOString() ?? null,
      createdAt: user.getCreatedAt().toISOString(),
      updatedAt: user.getUpdatedAt().toISOString(),
    };
  }
}
