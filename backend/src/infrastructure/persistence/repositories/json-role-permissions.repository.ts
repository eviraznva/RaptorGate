import {
  RolePermissionsFile,
  RolePermissionsFileSchema,
} from '../schemas/role-permissions.schema.js';
import { IRolePermissionsRepository } from '../../../domain/repositories/role-permissions.repository.js';
import { RolePermissionsJsonMapper } from '../mappers/role-permissions-json.mapper.js';
import { RolePermission } from '../../../domain/entities/role-permissions.entity.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import { Inject } from '@nestjs/common';
import { join } from 'node:path';

export class JsonRolePermissionsRepository implements IRolePermissionsRepository {
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/role_permissions.json',
  );

  constructor(
    @Inject(Mutex) private readonly mutex: Mutex,
    @Inject(FileStore) private readonly fileStore: FileStore,
  ) {}

  private async readPayload(): Promise<RolePermissionsFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return RolePermissionsFileSchema.parse(raw);
  }

  async save(rolePermission: RolePermission): Promise<void> {
    const rolePermissions = await this.readPayload();
    const next = RolePermissionsJsonMapper.toRecord(rolePermission);
    rolePermissions.items.push(next);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, rolePermissions);
    });
  }

  async findAll(): Promise<RolePermission[]> {
    const rolePermissions = await this.readPayload();
    if (!rolePermissions.items.length) return [];

    return rolePermissions.items.map((rp) =>
      RolePermissionsJsonMapper.toDomain(rp),
    );
  }
}
