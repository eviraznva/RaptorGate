import { ConfigurationSnapshot } from "../../../domain/entities/configuration-snapshot.entity.js";
import { ConfigurationSnapshotRecord } from "../schemas/configuration-snapshots.schema.js";
import { SnapshotType } from "../../../domain/value-objects/snapshot-type.vo.js";
import { Checksum } from "../../../domain/value-objects/checksum.vo.js";

export class ConfigurationSnapshotJsonMapper {
	static toDomain(record: ConfigurationSnapshotRecord): ConfigurationSnapshot {
		return ConfigurationSnapshot.create(
			record.id,
			record.versionNumber,
			SnapshotType.create(record.snapshotType),
			Checksum.create(record.checksum),
			record.isActive,
			record.payloadJson,
			record.changeSummary || null,
			new Date(record.createdAt),
			record.createdBy,
		);
	}

	static toRecord(
		snapshot: ConfigurationSnapshot,
	): ConfigurationSnapshotRecord {
		return {
			id: snapshot.getId(),
			versionNumber: snapshot.getVersionNumber(),
			snapshotType: snapshot.getSnapshotType().getValue(),
			checksum: snapshot.getChecksum().getValue(),
			isActive: snapshot.getIsActive(),
			payloadJson: snapshot.getPayloadJson(),
			createdAt: snapshot.getCreatedAt().toISOString(),
			createdBy: snapshot.getCreatedBy(),
			changeSummary: snapshot.getChangesSummary() ?? null,
		};
	}
}
