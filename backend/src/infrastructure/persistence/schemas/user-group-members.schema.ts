import { pgTable, timestamp, uuid } from 'drizzle-orm/pg-core';
import { identityUsersTable } from './identity-users.schema';
import { userGroupsTable } from './user-groups.schema';
import { defineRelations } from 'drizzle-orm';

export const userGroupMembersTable = pgTable('user_group_members', {
  id: uuid('id').primaryKey(),
  groupId: uuid('group_id')
    .notNull()
    .references(() => userGroupsTable.id, { onDelete: 'cascade' }),
  identityUserId: uuid('identity_user_id')
    .notNull()
    .references(() => identityUsersTable.id, { onDelete: 'no action' }),
  joinedAt: timestamp('joined_at').notNull(),
});

export const userGroupMembersRelations = defineRelations(
  {
    identityUsersTable,
    userGroupsTable,
    userGroupMembersTable,
  },
  (r) => ({
    userGroupMembersTable: {
      identityUser: r.one.identityUsersTable({
        from: r.userGroupMembersTable.identityUserId,
        to: r.identityUsersTable.id,
      }),

      userGroup: r.one.userGroupsTable({
        from: r.userGroupMembersTable.groupId,
        to: r.userGroupsTable.id,
      }),
    },

    identityUsersTable: {
      userGroupMembers: r.many.userGroupMembersTable(),
    },

    userGroupsTable: {
      userGroupMembers: r.many.userGroupMembersTable(),
    },
  }),
);
