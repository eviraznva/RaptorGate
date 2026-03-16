import { IConfigSnapshotRepository } from 'src/domain/repositories/config-snapshot.repository';
import { ConfigurationSnapshot } from 'src/domain/entities/configuration-snapshot.entity';
import { configurationSnapshotsTable } from '../schemas/configuration-snapshots.schema';
import { ConfigurationSnapshotMapper } from '../mappers/configuration-snapshot.mapper';
import { DB_CONNECTION } from '../database/database.module';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Inject, Injectable } from '@nestjs/common';
import { eq, desc } from 'drizzle-orm';

@Injectable()
export class DrizzleConfigSnapshotRepository implements IConfigSnapshotRepository {
  constructor(@Inject(DB_CONNECTION) private readonly db: NodePgDatabase) {}

  async getActiveSnapshot(): Promise<ConfigurationSnapshot | null> {
    const rows = await this.db
      .select()
      .from(configurationSnapshotsTable)
      .where(eq(configurationSnapshotsTable.isActive, true))
      .orderBy(desc(configurationSnapshotsTable.versionNumber))
      .limit(1);

    const row = rows[0];

    if (!row) return null;

    return ConfigurationSnapshotMapper.toDomain(row);
  }

  async save(snapshot: ConfigurationSnapshot): Promise<void> {
    await this.db.insert(configurationSnapshotsTable).values({
      id: snapshot.getId(),
      versionNumber: snapshot.getVersionNumber(),
      snapshotType: snapshot.getSnapshotType().getValue(),
      checksum: snapshot.getChecksum().getValue(),
      isActive: snapshot.getIsActive(),
      payloadJson: snapshot.getPayloadJson(),
      changeSummary: snapshot.getChangesSummary() ?? undefined,
      createdAt: snapshot.getCreatedAt(),
      createdBy: '00000000-0000-0000-0000-000000000000', // TODO: z kontekstu auth
    });
  }
}
