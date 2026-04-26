import { ZoneInterface } from '../entities/zone-interface.entity.js';

export interface IZoneInterfaceRepository {
  save(zoneInterface: ZoneInterface): Promise<void>;
  findById(id: string): Promise<ZoneInterface | null>;
  findAll(): Promise<ZoneInterface[]>;
  overwriteAll(zoneInterfaces: ZoneInterface[]): Promise<void>;
}

export const ZONE_INTERFACE_REPOSITORY_TOKEN = Symbol(
  'ZONE_INTERFACE_REPOSITORY_TOKEN',
);
