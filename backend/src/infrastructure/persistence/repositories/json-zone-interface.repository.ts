import { join } from 'node:path';
import { Inject, Injectable } from '@nestjs/common';
import { ZoneInterface } from '../../../domain/entities/zone-interface.entity.js';
import { IZoneInterfaceRepository } from '../../../domain/repositories/zone-interface.repository.js';
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
    const zoneInterfaces = await this.readPayload();
    const next = ZoneInterfaceJsonMapper.toRecord(zoneInterface);

    const existingRow = await this.findById(zoneInterface.getId());
    if (existingRow) {
      zoneInterfaces.items = zoneInterfaces.items.map((item) =>
        item.id === zoneInterface.getId() ? next : item,
      );
    } else {
      zoneInterfaces.items.push(next);
    }

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, zoneInterfaces);
    });
  }

  async overwriteAll(zoneInterfaces: ZoneInterface[]): Promise<void> {
    const items = zoneInterfaces.map((zoneInterface) =>
      ZoneInterfaceJsonMapper.toRecord(zoneInterface),
    );

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, { items });
    });
  }

  async findById(id: string): Promise<ZoneInterface | null> {
    const zoneInterfaces = await this.readPayload();
    const zoneInterfaceById = zoneInterfaces.items.find(
      (item) => item.id === id,
    );

    if (!zoneInterfaceById) return null;

    return ZoneInterfaceJsonMapper.toDomain(zoneInterfaceById);
  }

  async findAll(): Promise<ZoneInterface[]> {
    const zoneInterfaces = await this.readPayload();

    return zoneInterfaces.items.map((item) =>
      ZoneInterfaceJsonMapper.toDomain(item),
    );
  }
}
