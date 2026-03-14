import { User } from 'src/domain/entities/user.entity';
import { usersTable } from '../schemas/users.schema';
import { InferSelectModel } from 'drizzle-orm';

type UserRecord = InferSelectModel<typeof usersTable>;

export class UserMapper {
  static toDomain(record: UserRecord): User {
    return User.create(
      record.id,
      record.username,
      record.passwordHash,
      record.refreshToken,
      record.role,
      record.createdAt,
      record.updatedAt,
    );
  }

  static toPersistence(user: User) {
    return {
      id: user.getId(),
      username: user.getUsername(),
      passwordHash: user.getPasswordHash(),
      refreshToken: user.getRefreshToken(),
      role: user.getRole(),
      createdAt: user.getCreatedAt(),
      updatedAt: user.getUpdatedAt(),
    };
  }
}
