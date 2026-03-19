import { IUserRepository } from 'src/domain/repositories/user.repository';
import { UsersFile, UsersFileSchema } from '../schemas/users.schema';
import { UserJsonMapper } from '../mappers/user-json.mapper';
import { User } from 'src/domain/entities/user.entity';
import { Inject, Injectable } from '@nestjs/common';
import { FileStore } from '../json/file-store';
import { Mutex } from '../json/file-mutex';
import { join } from 'node:path';

@Injectable()
export class JsonUserRepository implements IUserRepository {
  private readonly filePath = join(process.cwd(), 'data/json-db/users.json');

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<UsersFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return UsersFileSchema.parse(raw);
  }

  async save(user: User): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();

      const next = UserJsonMapper.toRecord(user);

      const idx = payload.items.findIndex((i) => i.id === next.id);
      if (idx >= 0) payload.items[idx] = next;
      else payload.items.push(next);

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async findByUsername(username: string): Promise<User | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((i) => i.username === username);

    return row ? UserJsonMapper.toDomain(row) : null;
  }

  async findById(id: string): Promise<User | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((i) => i.id === id);

    return row ? UserJsonMapper.toDomain(row) : null;
  }

  async findAll(): Promise<User[]> {
    const payload = await this.readPayload();

    return payload.items.map((i) => UserJsonMapper.toDomain(i));
  }

  async deleteById(id: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      payload.items = payload.items.filter((i) => i.id !== id);

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async setRefreshToken(
    id: string,
    refreshToken: string | null,
    refreshTokenExpiry: Date | null,
  ): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      const row = payload.items.find((i) => i.id === id);

      if (!row) return;

      row.refreshToken = refreshToken;
      row.refreshTokenExpiry = refreshTokenExpiry?.toISOString() ?? null;
      row.updatedAt = new Date().toISOString();

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
