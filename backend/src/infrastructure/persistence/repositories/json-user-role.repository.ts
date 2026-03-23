import {
  UserRolesFile,
  UserRolesFileSchema,
} from '../schemas/user-roles.schema';
import { IUserRolesRepository } from 'src/domain/repositories/user-roles.repository';
import { UserRoleJsonMapper } from '../mappers/user-role-jsom.mapper';
import { UserRole } from 'src/domain/entities/user-roles.entity';
import { FileStore } from '../json/file-store';
import { Mutex } from '../json/file-mutex';
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
