import {
  boolean,
  integer,
  pgTable,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';
import { usersTable } from './users.schema';
import { defineRelations } from 'drizzle-orm';

export const natRulesTable = pgTable('nat_rules', {
  id: uuid('id').primaryKey(),
  type: varchar('type', { length: 16 }).notNull(),
  isActive: boolean('is_active').notNull().default(true),
  srcIp: varchar('src_ip', { length: 64 }),
  dstIp: varchar('dst_ip', { length: 64 }),
  srcPort: integer('src_port'),
  dstPort: integer('dst_port'),
  translatedIp: varchar('translated_ip', { length: 64 }),
  translatedPort: integer('translated_port'),
  priority: integer('priority').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const natRulesRelations = defineRelations(
  {
    usersTable,
    natRulesTable,
  },
  (r) => ({
    natRulesTable: {
      author: r.one.usersTable({
        from: r.natRulesTable.createdBy,
        to: r.usersTable.id,
      }),
    },
    usersTable: {
      natRules: r.many.natRulesTable(),
    },
  }),
);
