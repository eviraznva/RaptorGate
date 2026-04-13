export class RolePermission {
	constructor(
		private readonly roleId: string,
		private readonly permissionId: string,
	) {}

	static create(roleId: string, permissionId: string): RolePermission {
		return new RolePermission(roleId, permissionId);
	}

	public getRoleId(): string {
		return this.roleId;
	}

	public getPermissionId(): string {
		return this.permissionId;
	}
}
