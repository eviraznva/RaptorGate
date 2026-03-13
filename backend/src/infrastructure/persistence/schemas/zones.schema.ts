import {
  boolean,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';
import { usersTable } from './users.schema';
import { defineRelations } from 'drizzle-orm';

export const zonesTable = pgTable('zones', {
  id: uuid('id').primaryKey(),
  name: varchar('name', { length: 64 }).notNull(),
  description: text('description'),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const zonesRelations = defineRelations(
  {
    usersTable,
    zonesTable,
  },
  (r) => ({
    zonesTable: {
      author: r.one.usersTable({
        from: r.zonesTable.createdBy,
        to: r.usersTable.id,
      }),
    },
    usersTable: {
      zones: r.many.zonesTable(),
    },
  }),
);
