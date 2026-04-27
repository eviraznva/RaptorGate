import { join } from 'node:path';
import { Inject, Injectable } from '@nestjs/common';
import { ZoneInterface } from '../../../domain/entities/zone-interface.entity.js';
import {
  IZoneInterfaceRepository,
} from '../../../domain/repositories/zone-interface.repository.js';
import { Mutex } from '../json/file-mutex.js';
import { FileStore } from '../json/file-store.js';
import { ZoneInterfaceJsonMapper } from '../mappers/zone-interface-json.mapper.js';
import {
  ZoneInterfacesFile,
  ZoneInterfacesFileSchema,
} from '../schemas/zone-interfaces.schema.js';

@Injectable()
export class JsonZoneInterfaceRepository implements IZoneInterfaceRepository {
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/zone_interfaces.json',
  );

  constructor(
    @Inject(Mutex) private readonly mutex: Mutex,
    @Inject(FileStore) private readonly fileStore: FileStore,
  ) {}

  private async readPayload(): Promise<ZoneInterfacesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return ZoneInterfacesFileSchema.parse(raw);
  }

  async save(zoneInterface: ZoneInterface): Promise<void> {
    const payload = await this.readPayload();
    const next = ZoneInterfaceJsonMapper.toRecord(zoneInterface);
    const existing = await this.findById(zoneInterface.getId());

    if (existing) {
      payload.items = payload.items.map((item) =>
        item.id === zoneInterface.getId() ? next : item,
      );
    } else {
      payload.items.push(next);
    }

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async findById(id: string): Promise<ZoneInterface | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((item) => item.id === id);
    if (!row) return null;

    return ZoneInterfaceJsonMapper.toDomain(row);
  }

  async findAll(): Promise<ZoneInterface[]> {
    const payload = await this.readPayload();
    return payload.items.map((item) => ZoneInterfaceJsonMapper.toDomain(item));
  }

  async findByZoneId(zoneId: string): Promise<ZoneInterface[]> {
    const payload = await this.readPayload();
    return payload.items
      .filter((item) => item.zoneId === zoneId)
      .map((item) => ZoneInterfaceJsonMapper.toDomain(item));
  }

  async findByInterfaceName(interfaceName: string): Promise<ZoneInterface | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((item) => item.interfaceName === interfaceName);
    if (!row) return null;

    return ZoneInterfaceJsonMapper.toDomain(row);
  }

  async overwriteAll(zoneInterfaces: ZoneInterface[]): Promise<void> {
    const items = zoneInterfaces.map((zoneInterface) =>
      ZoneInterfaceJsonMapper.toRecord(zoneInterface),
    );

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, { items });
    });
  }

  async delete(id: string): Promise<void> {
    const payload = await this.readPayload();
    payload.items = payload.items.filter((item) => item.id !== id);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
