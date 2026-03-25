import { Role } from '../entities/role.entity';

export interface IRoleRepository {
  findById(id: string): Promise<Role | null>;
  findByName(name: string): Promise<Role | null>;
  findByUserId(userId: string): Promise<Role[]>;
  findAll(): Promise<Role[]>;
  save(role: { id: string; name: string; description?: string }): Promise<void>;
  assignToUser(userId: string, roleId: string): Promise<void>;
  removeFromUser(userId: string, roleId: string): Promise<void>;
  setUserRoles(userId: string, roleIds: string[]): Promise<void>;
  addPermissionToRole(roleId: string, permissionId: string): Promise<void>;
  setRolePermissions(roleId: string, permissionIds: string[]): Promise<void>;
}

export const ROLE_REPOSITORY_TOKEN = Symbol('ROLE_REPOSITORY_TOKEN');
