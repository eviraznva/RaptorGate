import { Permission } from 'src/domain/entities/permission.entity';
import { Role } from 'src/domain/entities/role.entity';
import { rolesTable } from '../schemas/roles.schema';
import { InferSelectModel } from 'drizzle-orm';

type RoleRecord = InferSelectModel<typeof rolesTable>;

export class RoleMapper {
  static toDomain(record: RoleRecord, permissions: Permission[] = []): Role {
    return Role.create(
      record.id,
      record.name,
      record.description ?? null,
      permissions,
    );
  }
}
