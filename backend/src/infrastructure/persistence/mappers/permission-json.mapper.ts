import { Permission } from 'src/domain/entities/permission.entity';
import { PermissionRecord } from '../schemas/permissions.schema';

export class PermissionJsonMapper {
  static toDomain(record: PermissionRecord): Permission {
    return Permission.create(
      record.id,
      record.name,
      record.description ?? null,
    );
  }

  static toRecord(permission: Permission): PermissionRecord {
    return {
      id: permission.getId(),
      name: permission.getName(),
      description: permission.getDescription(),
    };
  }
}
