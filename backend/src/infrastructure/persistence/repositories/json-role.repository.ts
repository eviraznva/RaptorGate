import {
  RolePermissionsFile,
  RolePermissionsFileSchema,
} from '../schemas/role-permissions.schema.js';
import {
  PermissionsFile,
  PermissionsFileSchema,
} from '../schemas/permissions.schema.js';
import {
  UserRolesFile,
  UserRolesFileSchema,
} from '../schemas/user-roles.schema.js';
import { IRoleRepository } from '../../../domain/repositories/role.repository.js';
import { RolesFile, RolesFileSchema } from '../schemas/roles.schema.js';
import { RoleJsonMapper } from '../mappers/role-json.mapper.js';
import { Role } from '../../../domain/entities/role.entity.js';
import { Inject, Injectable } from '@nestjs/common';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import { join } from 'node:path';

@Injectable()
export class JsonRoleRepository implements IRoleRepository {
  private readonly rolesPath = join(process.cwd(), 'data/json-db/roles.json');
  private readonly userRolesPath = join(
    process.cwd(),
    'data/json-db/user_roles.json',
  );

  private readonly rolePermissionsPath = join(
    process.cwd(),
    'data/json-db/role_permissions.json',
  );

  private readonly permissionsPath = join(
    process.cwd(),
    'data/json-db/permissions.json',
  );

  constructor(
    private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readRoles(): Promise<RolesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(
      this.rolesPath,
      {
        items: [],
      },
    );

    return RolesFileSchema.parse(raw);
  }

  private async readPermissions(): Promise<PermissionsFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(
      this.permissionsPath,
      {
        items: [],
      },
    );

    return PermissionsFileSchema.parse(raw);
  }

  private async readUserRoles(): Promise<UserRolesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(
      this.userRolesPath,
      {
        items: [],
      },
    );

    return UserRolesFileSchema.parse(raw);
  }

  private async readRolePermissions(): Promise<RolePermissionsFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(
      this.rolePermissionsPath,
      { items: [] },
    );

    return RolePermissionsFileSchema.parse(raw);
  }

  private async loadAll() {
    const [roles, userRoles, rolePermissions, permissions] = await Promise.all([
      this.readRoles(),
      this.readUserRoles(),
      this.readRolePermissions(),
      this.readPermissions(),
    ]);

    return { roles, userRoles, rolePermissions, permissions };
  }

  private buildRole(
    roleId: string,
    roles: RolesFile['items'],
    rolePermissions: RolePermissionsFile['items'],
    permissions: PermissionsFile['items'],
  ): Role | null {
    const role = roles.find((r) => r.id === roleId);
    if (!role) return null;

    const permissionIds = new Set(
      rolePermissions
        .filter((rp) => rp.roleId === role.id)
        .map((rp) => rp.permissionId),
    );

    const permissionsForRole = permissions.filter((p) =>
      permissionIds.has(p.id),
    );

    return RoleJsonMapper.toDomain(role, permissionsForRole);
  }

  async findById(id: string): Promise<Role | null> {
    const { roles, rolePermissions, permissions } = await this.loadAll();

    return this.buildRole(
      id,
      roles.items,
      rolePermissions.items,
      permissions.items,
    );
  }

  async findByName(name: string): Promise<Role | null> {
    const { roles, rolePermissions, permissions } = await this.loadAll();

    const role = roles.items.find((r) => r.name === name);
    if (!role) return null;

    return this.buildRole(
      role.id,
      roles.items,
      rolePermissions.items,
      permissions.items,
    );
  }

  async findByUserId(userId: string): Promise<Role[]> {
    const { roles, userRoles, rolePermissions, permissions } =
      await this.loadAll();

    const roleIds = userRoles.items
      .filter((ur) => ur.userId === userId)
      .map((ur) => ur.roleId);

    return roleIds
      .map((id) =>
        this.buildRole(
          id,
          roles.items,
          rolePermissions.items,
          permissions.items,
        ),
      )
      .filter((r): r is Role => r !== null);
  }

  async findAll(): Promise<Role[]> {
    const { roles, rolePermissions, permissions } = await this.loadAll();

    return roles.items
      .map((r) =>
        this.buildRole(
          r.id,
          roles.items,
          rolePermissions.items,
          permissions.items,
        ),
      )
      .filter((r): r is Role => r !== null);
  }

  async save(role: {
    id: string;
    name: string;
    description?: string;
  }): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readRoles();
      if (payload.items.some((x) => x.id === role.id || x.name === role.name))
        return;

      payload.items.push(RoleJsonMapper.toRecord(role));

      RolesFileSchema.parse(payload);

      await this.fileStore.writeJsonAtomic(this.rolesPath, payload);
    });
  }

  async assignToUser(userId: string, roleId: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readUserRoles();

      const exists = payload.items.some(
        (x) => x.userId === userId && x.roleId === roleId,
      );
      if (!exists) payload.items.push({ userId, roleId });

      UserRolesFileSchema.parse(payload);

      await this.fileStore.writeJsonAtomic(this.userRolesPath, payload);
    });
  }

  async removeFromUser(userId: string, roleId: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readUserRoles();
      payload.items = payload.items.filter(
        (x) => !(x.userId === userId && x.roleId === roleId),
      );

      UserRolesFileSchema.parse(payload);

      await this.fileStore.writeJsonAtomic(this.userRolesPath, payload);
    });
  }

  async setUserRoles(userId: string, roleIds: string[]): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readUserRoles();
      payload.items = payload.items.filter((x) => x.userId !== userId);
      payload.items.push(...roleIds.map((roleId) => ({ userId, roleId })));

      UserRolesFileSchema.parse(payload);

      await this.fileStore.writeJsonAtomic(this.userRolesPath, payload);
    });
  }

  async addPermissionToRole(
    roleId: string,
    permissionId: string,
  ): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readRolePermissions();

      const exists = payload.items.some(
        (x) => x.roleId === roleId && x.permissionId === permissionId,
      );
      if (!exists) payload.items.push({ roleId, permissionId });

      RolePermissionsFileSchema.parse(payload);

      await this.fileStore.writeJsonAtomic(this.rolePermissionsPath, payload);
    });
  }

  async setRolePermissions(
    roleId: string,
    permissionIds: string[],
  ): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readRolePermissions();
      payload.items = payload.items.filter((x) => x.roleId !== roleId);
      payload.items.push(
        ...permissionIds.map((permissionId) => ({ roleId, permissionId })),
      );

      RolePermissionsFileSchema.parse(payload);

      await this.fileStore.writeJsonAtomic(this.rolePermissionsPath, payload);
    });
  }
}
