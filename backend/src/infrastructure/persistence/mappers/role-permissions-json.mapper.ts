import { RolePermission } from 'src/domain/entities/role-permissions.entity';
import { RolePermissionRecord } from '../schemas/role-permissions.schema';

export class RolePermissionsJsonMapper {
  constructor() {}

  static toRecord(rolePermission: RolePermission): RolePermissionRecord {
    return {
      roleId: rolePermission.getRoleId(),
      permissionId: rolePermission.getPermissionId(),
    };
  }

  static toDomain(record: RolePermissionRecord): RolePermission {
    return RolePermission.create(record.roleId, record.permissionId);
  }
}
