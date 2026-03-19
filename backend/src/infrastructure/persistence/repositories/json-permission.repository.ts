import { IPermissionRepository } from 'src/domain/repositories/permission.repository';
import { Permission } from 'src/domain/entities/permission.entity';
import { FileStore } from '../json/file-store';
import { Injectable } from '@nestjs/common';
import { join } from 'node:path';

type PermissionRecord = {
  id: string;
  name: string;
  description?: string | null;
};

type RolePermissionRecord = { roleId: string; permissionId: string };

type PermissionsPayload = { items: PermissionRecord[] };

type RolePermissionsPayload = { items: RolePermissionRecord[] };

@Injectable()
export class JsonPermissionRepository implements IPermissionRepository {
  private readonly permissionsPath = join(
    process.cwd(),
    'data/json-db/permissions.json',
  );

  private readonly rolePermissionsPath = join(
    process.cwd(),
    'data/json-db/role_permissions.json',
  );

  constructor(private readonly fileStore: FileStore) {}

  private toDomain(row: PermissionRecord): Permission {
    return Permission.create(row.id, row.name, row.description ?? null);
  }

  async findAll(): Promise<Permission[]> {
    const payload = await this.fileStore.readJsonOrDefault<PermissionsPayload>(
      this.permissionsPath,
      { items: [] },
    );

    return payload.items.map((i) => this.toDomain(i));
  }

  async findByName(name: string): Promise<Permission | null> {
    const payload = await this.fileStore.readJsonOrDefault<PermissionsPayload>(
      this.permissionsPath,
      { items: [] },
    );

    const row = payload.items.find((i) => i.name === name);

    return row ? this.toDomain(row) : null;
  }
  async findByRoleId(roleId: string): Promise<Permission[]> {
    const [permissions, rolePermissions] = await Promise.all([
      this.fileStore.readJsonOrDefault<PermissionsPayload>(
        this.permissionsPath,
        {
          items: [],
        },
      ),

      this.fileStore.readJsonOrDefault<RolePermissionsPayload>(
        this.rolePermissionsPath,
        { items: [] },
      ),
    ]);

    const ids = new Set(
      rolePermissions.items
        .filter((rp) => rp.roleId === roleId)
        .map((rp) => rp.permissionId),
    );

    return permissions.items
      .filter((p) => ids.has(p.id))
      .map((p) => this.toDomain(p));
  }

  async saveAll(
    permissions: { id: string; name: string; description?: string }[],
  ): Promise<void> {
    const payload = await this.fileStore.readJsonOrDefault<PermissionsPayload>(
      this.permissionsPath,
      { items: [] },
    );

    for (const p of permissions) {
      if (payload.items.some((x) => x.id === p.id || x.name === p.name))
        continue;

      payload.items.push({
        id: p.id,
        name: p.name,
        description: p.description ?? null,
      });
    }

    await this.fileStore.writeJsonAtomic(this.permissionsPath, payload);
  }
}
