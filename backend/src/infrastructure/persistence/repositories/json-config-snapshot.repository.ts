import { IConfigSnapshotRepository } from '../../../domain/repositories/config-snapshot.repository';
import { ConfigurationSnapshotsFileSchema } from '../schemas/configuration-snapshots.schema';
import { ConfigurationSnapshotJsonMapper } from '../mappers/configuration-snapshots.mapper';
import { ConfigurationSnapshot } from '../../../domain/entities/configuration-snapshot.entity';
import { FileStore } from '../json/file-store';
import { Mutex } from '../json/file-mutex';
import { Inject } from '@nestjs/common';
import { join } from 'node:path';

export class JsonConfigSnapshotRepository implements IConfigSnapshotRepository {
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/configuration_snapshots.json',
  );
  constructor(
    @Inject(Mutex) private readonly mutex: Mutex,
    @Inject(FileStore) private readonly fileStore: FileStore,
  ) {}

  async save(configSnapshot: ConfigurationSnapshot): Promise<void> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    const snapshots = ConfigurationSnapshotsFileSchema.parse(raw);
    const next = ConfigurationSnapshotJsonMapper.toRecord(configSnapshot);
    snapshots.items.push(next);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, snapshots);
    });
  }

  async getActiveSnapshot(): Promise<ConfigurationSnapshot | null> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    const snapshots = ConfigurationSnapshotsFileSchema.parse(raw);
    const activeSnapshot = snapshots.items.find(
      (snapshot) => snapshot.isActive,
    );

    if (!activeSnapshot) return null;

    return ConfigurationSnapshotJsonMapper.toDomain(activeSnapshot);
  }
}
