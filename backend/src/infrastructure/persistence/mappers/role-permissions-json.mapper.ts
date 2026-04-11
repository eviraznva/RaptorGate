import { RolePermission } from "../../../domain/entities/role-permissions.entity.js";
import { RolePermissionRecord } from "../schemas/role-permissions.schema.js";

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
