import {
  boolean,
  pgTable,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';
import { usersTable } from './users.schema';
import { defineRelations } from 'drizzle-orm';

export const mlModelsTable = pgTable('ml_models', {
  id: uuid('id').primaryKey(),
  name: varchar('name', { length: 128 }).notNull(),
  version: varchar('version', { length: 64 }).notNull(),
  artifactPath: varchar('artifact_path', { length: 255 }).notNull(),
  checksum: varchar('checksum', { length: 128 }).notNull(),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  activatedAt: timestamp('activated_at'),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const mlModelsRelations = defineRelations(
  {
    usersTable,
    mlModelsTable,
  },
  (r) => ({
    mlModelsTable: {
      author: r.one.usersTable({
        from: r.mlModelsTable.createdBy,
        to: r.usersTable.id,
      }),
    },
    usersTable: {
      mlModels: r.many.mlModelsTable(),
    },
  }),
);
