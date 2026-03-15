import { ConfigurationSnapshot } from 'src/domain/entities/configuration-snapshot.entity';
import { Checksum } from 'src/domain/value-objects/checksum.vo';
import { SnapshotType } from 'src/domain/value-objects/snapshot-type.vo';
import { configurationSnapshotsTable } from '../schemas/configuration-snapshots.schema';
import { InferSelectModel } from 'drizzle-orm';

type ConfigurationSnapshotRecord = InferSelectModel<
  typeof configurationSnapshotsTable
>;

export class ConfigurationSnapshotMapper {
  static toDomain(record: ConfigurationSnapshotRecord) {
    return ConfigurationSnapshot.create(
      record.id,
      record.versionNumber,
      SnapshotType.create(record.snapshotType),
      Checksum.create(record.checksum),
      record.isActive,
      record.payloadJson,
      record.changeSummary ?? null,
      record.createdAt,
    );
  }

  static toPersistence(snapshot: ConfigurationSnapshot) {
    return {
      id: snapshot.getId(),
      versionNumber: snapshot.getVersionNumber(),
      snapshotType: snapshot.getSnapshotType().getValue(),
      checksum: snapshot.getChecksum().getValue(),
      isActive: snapshot.getIsActive(),
      payloadJson: snapshot.getPayloadJson(),
      changeSummary: snapshot.getChangesSummary() ?? undefined,
      createdAt: snapshot.getCreatedAt(),
    };
  }
}
