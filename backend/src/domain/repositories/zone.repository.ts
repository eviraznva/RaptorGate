import { Zone } from "../entities/zone.entity.js";

export interface IZoneRepository {
	save(zone: Zone, createdBy: string): Promise<void>;
	findById(id: string): Promise<Zone | null>;
	findAll(): Promise<Zone[]>;
	findByName(name: string): Promise<Zone | null>;
	findActive(): Promise<Zone[]>;
	overwriteAll(zones: Zone[]): Promise<void>;
	delete(id: string): Promise<void>;
}

export const ZONE_REPOSITORY_TOKEN = Symbol("ZONE_REPOSITORY_TOKEN");
