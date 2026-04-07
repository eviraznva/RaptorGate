import {
	ZonePair,
	ZonePairPolicy,
} from "../../../domain/entities/zone-pair.entity.js";
import { ZonePairRecord } from "../schemas/zone-pairs.schema.js";

export class ZonePairJsonMapper {
	constructor() {}

	static toDomain(record: ZonePairRecord): ZonePair {
		return ZonePair.create(
			record.id,
			record.srcZoneId,
			record.dstZoneID,
			record.defaultPolicy as ZonePairPolicy,
			new Date(record.createdAt),
			record.createdBy,
		);
	}

	static toRecord(zonePair: ZonePair): ZonePairRecord {
		return {
			id: zonePair.getId(),
			srcZoneId: zonePair.getSrcZoneId(),
			dstZoneID: zonePair.getDstZoneId(),
			defaultPolicy: zonePair.getDefaultPolicy(),
			createdAt: zonePair.getCreatedAt().toISOString(),
			createdBy: zonePair.getCreatedBy(),
		};
	}
}
