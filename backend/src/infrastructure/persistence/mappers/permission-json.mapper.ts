import { Permission } from "../../../domain/entities/permission.entity.js";
import { PermissionRecord } from "../schemas/permissions.schema.js";

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
