import {
  boolean,
  integer,
  json,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';
import { usersTable } from './users.schema';
import { defineRelations } from 'drizzle-orm';

export const configurationSnapshotsTable = pgTable('configuration_snapshots', {
  id: uuid('id').primaryKey(),
  versionNumber: integer('version_number').notNull(),
  snapshotType: varchar('snapshot_type', { length: 32 }).notNull(),
  checksum: varchar('checksum', { length: 128 }).notNull(),
  isActive: boolean('is_active').notNull().default(true),
  payloadJson: json('payload_json').notNull(),
  changeSummary: text(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const configurationSnapshotsRelations = defineRelations(
  {
    usersTable,
    configurationSnapshotsTable,
  },
  (r) => ({
    configurationSnapshotsTable: {
      author: r.one.usersTable({
        from: r.configurationSnapshotsTable.createdBy,
        to: r.usersTable.id,
      }),
    },
    usersTable: {
      configurationSnapshots: r.many.configurationSnapshotsTable(),
    },
  }),
);
