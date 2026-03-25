import { UserRole } from 'src/domain/entities/user-roles.entity';
import { UserRoleRecord } from '../schemas/user-roles.schema';

export class UserRoleJsonMapper {
  constructor() {}

  static toRecord(userRole: UserRole): UserRoleRecord {
    return {
      roleId: userRole.getRoleId(),
      userId: userRole.getUserId(),
    };
  }

  static toDomain(record: UserRoleRecord): UserRole {
    return UserRole.create(record.userId, record.roleId);
  }
}
