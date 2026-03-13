import { pgTable, text, timestamp, uuid, varchar } from 'drizzle-orm/pg-core';
import { usersTable } from './users.schema';
import { defineRelations } from 'drizzle-orm';

export const userGroupsTable = pgTable('user_groups', {
  id: uuid('id').primaryKey(),
  name: varchar('name', { length: 64 }).notNull(),
  description: text('description'),
  source: varchar('source', { length: 16 }).notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const userGroupsRelations = defineRelations(
  {
    usersTable,
    userGroupsTable,
  },
  (r) => ({
    userGroupsTable: {
      author: r.one.usersTable({
        from: r.userGroupsTable.createdBy,
        to: r.usersTable.id,
      }),
    },
    usersTable: {
      userGroups: r.many.userGroupsTable(),
    },
  }),
);
