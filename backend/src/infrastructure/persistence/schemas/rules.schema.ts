import {
  boolean,
  pgTable,
  smallint,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';
import { usersTable } from './users.schema';
import { zonePairsTable } from './zone-pairs.schema';
import { defineRelations } from 'drizzle-orm';

export const rulesTable = pgTable('rules', {
  id: uuid('id').primaryKey(),
  name: varchar('name', { length: 128 }).notNull(),
  description: text(),
  zonePairId: uuid('zone_pair_id')
    .notNull()
    .references(() => zonePairsTable.id, { onDelete: 'no action' }),
  isActive: boolean('is_active').notNull().default(true),
  content: text().notNull(),
  priority: smallint('priority').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const rulesRelations = defineRelations(
  {
    usersTable,
    zonePairsTable,
    rulesTable,
  },
  (r) => ({
    rulesTable: {
      author: r.one.usersTable({
        from: r.rulesTable.createdBy,
        to: r.usersTable.id,
      }),
      zonePair: r.one.zonePairsTable({
        from: r.rulesTable.zonePairId,
        to: r.zonePairsTable.id,
      }),
    },

    usersTable: {
      rules: r.many.rulesTable(),
    },

    zonePairsTable: {
      rules: r.many.rulesTable(),
    },
  }),
);
