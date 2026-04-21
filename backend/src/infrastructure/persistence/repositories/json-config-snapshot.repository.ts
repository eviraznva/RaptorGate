import { join } from 'node:path';
import { Inject, Logger } from '@nestjs/common';
import { ConfigurationSnapshot } from '../../../domain/entities/configuration-snapshot.entity.js';
import { IConfigSnapshotRepository } from '../../../domain/repositories/config-snapshot.repository.js';
import { Mutex } from '../json/file-mutex.js';
import { FileStore } from '../json/file-store.js';
import {
  mapConfigBundlePayloadToDomain,
  mapConfigSnapshotToPayloadRecord,
} from '../mappers/config-payload.mapper.js';
import { ConfigurationSnapshotJsonMapper } from '../mappers/configuration-snapshots.mapper.js';
import {
  ConfigurationSnapshotsFile,
  ConfigurationSnapshotsFileSchema,
} from '../schemas/configuration-snapshots.schema.js';

export class JsonConfigSnapshotRepository implements IConfigSnapshotRepository {
  private readonly logger = new Logger(JsonConfigSnapshotRepository.name);
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

    const payload = mapConfigSnapshotToPayloadRecord(configSnapshot);
    configSnapshot.setPayloadJson(JSON.stringify(payload));

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

    return snapshots.items.map((snapshot) => {
      const configSnapshotToDomain =
        ConfigurationSnapshotJsonMapper.toDomain(snapshot);

      const payloadToDomain = mapConfigBundlePayloadToDomain(
        configSnapshotToDomain,
      );

      configSnapshotToDomain.setPayloadJson(payloadToDomain);
      return configSnapshotToDomain;
    });
  }

  async findActiveSnapshot(): Promise<ConfigurationSnapshot | null> {
    const snapshots = await this.readPayload();

    const activeSnapshot = snapshots.items.find(
      (snapshot) => snapshot.isActive,
    );
    if (!activeSnapshot) return null;

    const activeSnapshotToDomain =
      ConfigurationSnapshotJsonMapper.toDomain(activeSnapshot);
    const payloadToDomain = mapConfigBundlePayloadToDomain(
      activeSnapshotToDomain,
    );

    activeSnapshotToDomain.setPayloadJson(payloadToDomain);

    return activeSnapshotToDomain;
  }

  async findById(id: string): Promise<ConfigurationSnapshot | null> {
    const snapshots = await this.readPayload();
    const snapshotById = snapshots.items.find((s) => s.id === id);

    if (!snapshotById) return null;

    const configSnapshotToDomain =
      ConfigurationSnapshotJsonMapper.toDomain(snapshotById);

    const payloadToDomain = mapConfigBundlePayloadToDomain(
      configSnapshotToDomain,
    );

    configSnapshotToDomain.setPayloadJson(payloadToDomain);

    return configSnapshotToDomain;
  }
}
