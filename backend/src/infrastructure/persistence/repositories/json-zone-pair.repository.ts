import { IZonePairRepository } from '../../../domain/repositories/zone-pair.repository.js';
import {
  ZonePairsFile,
  ZonePairsFileSchema,
} from '../schemas/zone-pairs.schema.js';
import { ZonePairJsonMapper } from '../mappers/zone-pair-json.mapper.js';
import { ZonePair } from '../../../domain/entities/zone-pair.entity.js';
import { FileStore } from '../json/file-store.js';
import { Mutex } from '../json/file-mutex.js';
import { Inject } from '@nestjs/common';
import { join } from 'path';

export class JsonZonePairRepository implements IZonePairRepository {
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/zone_pairs.json',
  );

  constructor(
    @Inject(Mutex) private readonly mutex: Mutex,
    @Inject(FileStore) private readonly fileStore: FileStore,
  ) {}

  private async readPayload(): Promise<ZonePairsFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return ZonePairsFileSchema.parse(raw);
  }

  async save(zonePair: ZonePair): Promise<void> {
    const zonePairs = await this.readPayload();
    const next = ZonePairJsonMapper.toRecord(zonePair);

    const existingRow = await this.findById(zonePair.getId());
    if (existingRow) {
      zonePairs.items = zonePairs.items.map((z) =>
        z.id === zonePair.getId() ? next : z,
      );
    } else {
      zonePairs.items.push(next);
    }

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, zonePairs);
    });
  }

  async overwriteAll(zonePairs: ZonePair[]): Promise<void> {
    const toZonePairs = zonePairs.map((zone) =>
      ZonePairJsonMapper.toRecord(zone),
    );

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, {
        items: toZonePairs,
      });
    });
  }

  async findById(id: string): Promise<ZonePair | null> {
    const zonePairs = await this.readPayload();
    const zonePairById = zonePairs.items.find((z) => z.id === id);

    if (!zonePairById) return null;

    return ZonePairJsonMapper.toDomain(zonePairById);
  }

  async findByZoneIds(
    srcZoneId: string,
    dstZoneId: string,
  ): Promise<ZonePair | null> {
    const zonePairs = await this.readPayload();
    const zonePairByZoneIds = zonePairs.items.find(
      (z) => z.srcZoneId === srcZoneId && z.dstZoneID === dstZoneId,
    );

    if (!zonePairByZoneIds) return null;

    return ZonePairJsonMapper.toDomain(zonePairByZoneIds);
  }

  async findBySrcZoneId(srcZoneId: string): Promise<ZonePair[]> {
    const zonePairs = await this.readPayload();
    zonePairs.items = zonePairs.items.filter((z) => z.srcZoneId === srcZoneId);

    return zonePairs.items.map((z) => ZonePairJsonMapper.toDomain(z));
  }

  async findByDstZoneId(dstZoneId: string): Promise<ZonePair[]> {
    const zonePairs = await this.readPayload();
    zonePairs.items = zonePairs.items.filter((z) => z.dstZoneID === dstZoneId);

    return zonePairs.items.map((z) => ZonePairJsonMapper.toDomain(z));
  }

  async findAll(): Promise<ZonePair[]> {
    const zonePairs = await this.readPayload();
    if (!zonePairs) return [];

    return zonePairs.items.map((z) => ZonePairJsonMapper.toDomain(z));
  }

  async delete(id: string): Promise<void> {
    const zonePairs = await this.readPayload();
    zonePairs.items = zonePairs.items.filter((z) => z.id !== id);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, zonePairs);
    });
  }
}
