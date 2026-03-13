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

export const sslBypassListTable = pgTable('ssl_bypass_list', {
  id: uuid('id').primaryKey(),
  domain: varchar('domain', { length: 255 }).notNull(),
  reason: text().notNull(),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const sslBypassListRelations = defineRelations(
  {
    usersTable,
    sslBypassListTable,
  },
  (r) => ({
    sslBypassListTable: {
      author: r.one.usersTable({
        from: r.sslBypassListTable.createdBy,
        to: r.usersTable.id,
      }),
    },
    usersTable: {
      sslBypassList: r.many.sslBypassListTable(),
    },
  }),
);
