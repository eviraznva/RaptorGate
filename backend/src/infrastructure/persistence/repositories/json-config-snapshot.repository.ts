import { IConfigSnapshotRepository } from 'src/domain/repositories/config-snapshot.repository';
import {
  ConfigurationSnapshotsFile,
  ConfigurationSnapshotsFileSchema,
} from '../schemas/configuration-snapshots.schema';
import { ConfigurationSnapshotJsonMapper } from '../mappers/configuration-snapshots.mapper';
import { ConfigurationSnapshot } from 'src/domain/entities/configuration-snapshot.entity';
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

  private async readPayload(): Promise<ConfigurationSnapshotsFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return ConfigurationSnapshotsFileSchema.parse(raw);
  }

  async save(configSnapshot: ConfigurationSnapshot): Promise<void> {
    const snapshots = await this.readPayload();

    const next = ConfigurationSnapshotJsonMapper.toRecord(configSnapshot);

    const existingRow = await this.findById(configSnapshot.getId());
    if (existingRow) {
      snapshots.items = snapshots.items.map((s) =>
        s.id === configSnapshot.getId() ? next : s,
      );
    } else {
      snapshots.items.push(next);
    }

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, snapshots);
    });
  }

  async findAllSnapshots(): Promise<ConfigurationSnapshot[]> {
    const snapshots = await this.readPayload();

    return snapshots.items.map((snapshot) =>
      ConfigurationSnapshotJsonMapper.toDomain(snapshot),
    );
  }

  async findActiveSnapshot(): Promise<ConfigurationSnapshot | null> {
    const snapshots = await this.readPayload();

    const activeSnapshot = snapshots.items.find(
      (snapshot) => snapshot.isActive,
    );

    if (!activeSnapshot) return null;

    return ConfigurationSnapshotJsonMapper.toDomain(activeSnapshot);
  }

  async findById(id: string): Promise<ConfigurationSnapshot | null> {
    const snapshots = await this.readPayload();
    const snapshotById = snapshots.items.find((s) => s.id === id);

    if (!snapshotById) return null;

    return ConfigurationSnapshotJsonMapper.toDomain(snapshotById);
  }
}
