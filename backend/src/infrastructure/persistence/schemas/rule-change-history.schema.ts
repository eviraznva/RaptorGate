import { pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';
import { rulesTable } from './rules.schema';
import { usersTable } from './users.schema';
import { defineRelations } from 'drizzle-orm';

export const ruleChangeHistoryTable = pgTable('rule_change_history', {
  id: uuid('id').primaryKey(),
  ruleId: uuid('rule_id')
    .notNull()
    .references(() => rulesTable.id, { onDelete: 'no action' }),
  changedBy: uuid('changed_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
  modifiedAt: timestamp('modified_at').notNull(),
  content: text('content').notNull(),
});

export const ruleChangeHistoryRelations = defineRelations(
  {
    rulesTable,
    usersTable,
    ruleChangeHistoryTable,
  },
  (r) => ({
    ruleChangeHistoryTable: {
      author: r.one.usersTable({
        from: r.ruleChangeHistoryTable.changedBy,
        to: r.usersTable.id,
      }),
      rule: r.one.rulesTable({
        from: r.ruleChangeHistoryTable.ruleId,
        to: r.rulesTable.id,
      }),
    },

    usersTable: {
      ruleChangeHistory: r.many.ruleChangeHistoryTable(),
    },

    rulesTable: {
      ruleChangeHistory: r.many.ruleChangeHistoryTable(),
    },
  }),
);
