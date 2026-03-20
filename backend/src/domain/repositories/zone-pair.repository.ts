import { ZonePair } from '../entities/zone-pair.entity';

export interface IZonePairRepository {
  save(zonePair: ZonePair): Promise<void>;
  findById(id: string): Promise<ZonePair | null>;
  findByZoneIds(srcZoneId: string, dstZoneId: string): Promise<ZonePair | null>;
  findBySrcZoneId(srcZoneId: string): Promise<ZonePair[]>;
  findByDstZoneId(dstZoneId: string): Promise<ZonePair[]>;
  findAll(): Promise<ZonePair[]>;
  delete(id: string): Promise<void>;
}

export const ZONE_PAIR_REPOSITORY_TOKEN = Symbol('ZONE_PAIR_REPOSITORY_TOKEN');
