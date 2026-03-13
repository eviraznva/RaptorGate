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

export const dnsBlacklistTable = pgTable('dns_blacklist', {
  id: uuid('id').primaryKey(),
  domain: varchar('domain', { length: 255 }).notNull(),
  reason: text('reason').notNull(),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const dnsBlacklistRelations = defineRelations(
  {
    usersTable,
    dnsBlacklistTable,
  },
  (r) => ({
    dnsBlacklistTable: {
      author: r.one.usersTable({
        from: r.dnsBlacklistTable.createdBy,
        to: r.usersTable.id,
      }),
    },
    usersTable: {
      dnsBlacklist: r.many.dnsBlacklistTable(),
    },
  }),
);
