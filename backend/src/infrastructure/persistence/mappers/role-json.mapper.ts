import { Permission } from '../../../domain/entities/permission.entity';
import { PermissionRecord } from '../schemas/permissions.schema';
import { Role } from '../../../domain/entities/role.entity';
import { RoleRecord } from '../schemas/roles.schema';

export class RoleJsonMapper {
  static toDomain(role: RoleRecord, permissions: PermissionRecord[]): Role {
    const mappedPermissions: Permission[] = permissions.map((p) =>
      Permission.create(p.id, p.name, p.description ?? null),
    );

    return Role.create(
      role.id,
      role.name,
      role.description ?? null,
      mappedPermissions,
    );
  }

  static toRecord(role: {
    id: string;
    name: string;
    description?: string;
  }): RoleRecord {
    return {
      id: role.id,
      name: role.name,
      description: role.description ?? null,
    };
  }
}
