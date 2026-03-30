import { IUserRolesRepository } from '../../../domain/repositories/user-roles.repository.js';
import {
  UserRolesFile,
  UserRolesFileSchema,
} from '../schemas/user-roles.schema.js';
import { UserRole } from '../../../domain/entities/user-roles.entity.js';
import { UserRoleJsonMapper } from '../mappers/user-role-jsom.mapper.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import { Inject } from '@nestjs/common';
import { join } from 'node:path';

export class JsonUserRoleRepository implements IUserRolesRepository {
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/user_roles.json',
  );

  private async readPayload(): Promise<UserRolesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return UserRolesFileSchema.parse(raw);
  }

  constructor(
    @Inject(Mutex) private readonly mutex: Mutex,
    @Inject(FileStore) private readonly fileStore: FileStore,
  ) {}

  async findAll(): Promise<UserRole[]> {
    const payload = await this.readPayload();
    if (!payload.items.length) return [];

    return payload.items.map((ur) => UserRoleJsonMapper.toDomain(ur));
  }
}
