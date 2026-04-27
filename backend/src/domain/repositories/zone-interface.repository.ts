import { ZoneInterface } from '../entities/zone-interface.entity.js';

export interface IZoneInterfaceRepository {
  save(zoneInterface: ZoneInterface): Promise<void>;
  findById(id: string): Promise<ZoneInterface | null>;
  findAll(): Promise<ZoneInterface[]>;
  findByZoneId(zoneId: string): Promise<ZoneInterface[]>;
  findByInterfaceName(interfaceName: string): Promise<ZoneInterface | null>;
  overwriteAll(zoneInterfaces: ZoneInterface[]): Promise<void>;
  delete(id: string): Promise<void>;
}

export const ZONE_INTERFACE_REPOSITORY_TOKEN = Symbol(
  'ZONE_INTERFACE_REPOSITORY_TOKEN',
);
