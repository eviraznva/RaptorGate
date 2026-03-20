import { IZoneRepository } from 'src/domain/repositories/zone.repository';
import { ZonesFile, ZonesFileSchema } from '../schemas/zones.schema';
import { ZoneJsonMapper } from '../mappers/zone-json.mapper';
import { Zone } from 'src/domain/entities/zone.entity';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { FileStore } from '../json/file-store';
import { Mutex } from '../json/file-mutex';
import { join } from 'node:path';

@Injectable()
export class JsonZoneRepository implements IZoneRepository {
  private readonly logger = new Logger(JsonZoneRepository.name);
  private readonly filePath = join(process.cwd(), 'data/json-db/zones.json');

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<ZonesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return ZonesFileSchema.parse(raw);
  }

  async save(zone: Zone, createdBy: string): Promise<void> {
    const zones = await this.readPayload();
    const next = ZoneJsonMapper.toRecord(zone, createdBy);

    const existingRow = await this.findById(zone.getId());
    if (existingRow) {
      zones.items = zones.items.map((z) => (z.id === zone.getId() ? next : z));
    } else {
      zones.items.push(next);
    }

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, zones);
    });
  }

  async findById(id: string): Promise<Zone | null> {
    const zones = await this.readPayload();
    const zoneById = zones.items.find((z) => z.id === id);

    if (!zoneById) return null;

    return ZoneJsonMapper.toDomain(zoneById);
  }

  async findAll(): Promise<Zone[]> {
    const zones = await this.readPayload();
    if (!zones.items.length) return [];

    return zones.items.map((z) => ZoneJsonMapper.toDomain(z));
  }

  async findByName(name: string): Promise<Zone | null> {
    const zones = await this.readPayload();
    const zoneByName = zones.items.find((z) => z.name === name);

    if (!zoneByName) return null;

    return ZoneJsonMapper.toDomain(zoneByName);
  }

  async findActive(): Promise<Zone[]> {
    const zones = await this.readPayload();
    const activeZones = zones.items.filter((z) => z.isActive);
    return activeZones.map((z) => ZoneJsonMapper.toDomain(z));
  }

  async delete(id: string): Promise<void> {
    const zones = await this.readPayload();

    zones.items = zones.items.filter((z) => z.id !== id);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, zones);
    });
  }
}
