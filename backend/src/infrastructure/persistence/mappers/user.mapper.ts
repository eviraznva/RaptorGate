import { User } from 'src/domain/entities/user.entity';
import { Role } from 'src/domain/entities/role.entity';
import { usersTable } from '../schemas/users.schema';
import { InferSelectModel } from 'drizzle-orm';

type UserRecord = InferSelectModel<typeof usersTable>;

export class UserMapper {
  static toDomain(record: UserRecord, roles: Role[] = []): User {
    return User.create(
      record.id,
      record.username,
      record.passwordHash,
      record.refreshToken,
      record.refreshTokenExpiry,
      record.createdAt,
      record.updatedAt,
      roles,
    );
  }

  static toPersistence(user: User) {
    return {
      id: user.getId(),
      username: user.getUsername(),
      passwordHash: user.getPasswordHash(),
      refreshToken: user.getRefreshToken(),
      refreshTokenExpiry: user.getRefreshTokenExpiry(),
      createdAt: user.getCreatedAt(),
      updatedAt: user.getUpdatedAt(),
    };
  }
}
