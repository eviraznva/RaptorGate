import { RolePermission } from '../entities/role-permissions.entity.js';

export interface IRolePermissionsRepository {
  save(rolePermission: RolePermission): Promise<void>;
  findAll(): Promise<RolePermission[]>;
}

export const ROLE_PERMISSIONS_REPOSITORY_TOKEN = Symbol(
  'ROLE_PERMISSIONS_REPOSITORY_TOKEN',
);
