import { Permission } from '../entities/permission.entity';

export interface IPermissionRepository {
  findAll(): Promise<Permission[]>;
  findByName(name: string): Promise<Permission | null>;
  findByRoleId(roleId: string): Promise<Permission[]>;
  saveAll(
    permissions: { id: string; name: string; description?: string }[],
  ): Promise<void>;
}

export const PERMISSION_REPOSITORY_TOKEN = Symbol(
  'PERMISSION_REPOSITORY_TOKEN',
);
