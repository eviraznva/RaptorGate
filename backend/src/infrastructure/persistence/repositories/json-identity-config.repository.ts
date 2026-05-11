import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { Inject, Injectable } from '@nestjs/common';
import { IdentityConfiguration } from '../../../domain/entities/identity-configuration.entity.js';
import { IIdentityConfigRepository } from '../../../domain/repositories/identity-config.repository.js';
import { Mutex } from '../json/file-mutex.js';
import { FileStore } from '../json/file-store.js';
import { IdentityConfigJsonMapper } from '../mappers/identity-config-json.mapper.js';
import { IdentityConfigurationRecordSchema } from '../schemas/identity-config.schema.js';

@Injectable()
export class JsonIdentityConfigRepository implements IIdentityConfigRepository {
  private readonly filePath = join(process.cwd(), 'data/json-db/identity-config.json');

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  async exists(): Promise<boolean> {
    try {
      await fs.access(this.filePath);
      return true;
    } catch (error: unknown) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        (error as { code?: string }).code === 'ENOENT'
      ) {
        return false;
      }

      throw error;
    }
  }

  async find(): Promise<IdentityConfiguration> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(
      this.filePath,
      IdentityConfigJsonMapper.emptyRecord(),
    );

    const record = IdentityConfigurationRecordSchema.parse(raw);

    return IdentityConfigJsonMapper.toDomain(record);
  }

  async save(config: IdentityConfiguration): Promise<void> {
    await this.overwrite(config);
  }

  async overwrite(config: IdentityConfiguration): Promise<void> {
    const record = IdentityConfigJsonMapper.toRecord(config);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, record);
    });
  }

  async mutate(
    transform: (
      config: IdentityConfiguration,
    ) => IdentityConfiguration | Promise<IdentityConfiguration>,
  ): Promise<IdentityConfiguration> {
    return this.mutex.runExclusive(async () => {
      const raw = await this.fileStore.readJsonOrDefault<unknown>(
        this.filePath,
        IdentityConfigJsonMapper.emptyRecord(),
      );
      const record = IdentityConfigurationRecordSchema.parse(raw);
      const current = IdentityConfigJsonMapper.toDomain(record);
      const next = await transform(current);

      await this.fileStore.writeJsonAtomic(
        this.filePath,
        IdentityConfigJsonMapper.toRecord(next),
      );

      return next;
    });
  }
}
