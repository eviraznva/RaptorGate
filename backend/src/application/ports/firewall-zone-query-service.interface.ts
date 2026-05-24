import type { Zone } from '../../domain/entities/zone.entity.js';
import type { ZoneInterface } from '../../domain/entities/zone-interface.entity.js';
import type { ZonePair } from '../../domain/entities/zone-pair.entity.js';

export interface IFirewallZoneQueryService {
  getZones(): Promise<Zone[]>;
  getZone(id: string): Promise<Zone | null>;
  getZoneInterfaces(): Promise<ZoneInterface[]>;
  getZoneInterface(id: string): Promise<ZoneInterface | null>;
  getLiveZoneInterfaces(): Promise<ZoneInterface[]>;
  setInterfaceState(id: string, isActive: boolean): Promise<void>;
  getZonePairs(): Promise<ZonePair[]>;
  getZonePair(id: string): Promise<ZonePair | null>;
}

export const FIREWALL_ZONE_QUERY_SERVICE_TOKEN = Symbol(
  'FIREWALL_ZONE_QUERY_SERVICE_TOKEN',
);
