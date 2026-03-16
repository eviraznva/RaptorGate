import { Permission } from 'src/domain/entities/permission.entity';
import { permissionsTable } from '../schemas/permissions.schema';
import { InferSelectModel } from 'drizzle-orm';

type PermissionRecord = InferSelectModel<typeof permissionsTable>;

export class PermissionMapper {
  static toDomain(record: PermissionRecord): Permission {
    return Permission.create(
      record.id,
      record.name,
      record.description ?? null,
    );
  }

  static toPersistence(permission: Permission): Omit<PermissionRecord, 'id'> {
    return {
      name: permission.getName(),
      description: permission.getDescription() ?? null,
    };
  }
}
