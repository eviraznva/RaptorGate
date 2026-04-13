import { UserRole } from "../../../domain/entities/user-roles.entity.js";
import { UserRoleRecord } from "../schemas/user-roles.schema.js";

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
