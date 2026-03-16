import { pgTable, uuid, varchar, primaryKey } from 'drizzle-orm/pg-core';
import { permissionsTable } from './permissions.schema';
import { usersTable } from './users.schema';

export const rolesTable = pgTable('roles', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 64 }).notNull().unique(),
  description: varchar('description', { length: 255 }),
});

export const rolePermissionsTable = pgTable(
  'role_permissions',
  {
    roleId: uuid('role_id')
      .notNull()
      .references(() => rolesTable.id, { onDelete: 'cascade' }),
    permissionId: uuid('permission_id')
      .notNull()
      .references(() => permissionsTable.id, { onDelete: 'cascade' }),
  },
  (table) => [primaryKey({ columns: [table.roleId, table.permissionId] })],
);

export const userRolesTable = pgTable(
  'user_roles',
  {
    userId: uuid('user_id')
      .notNull()
      .references(() => usersTable.id, { onDelete: 'cascade' }),
    roleId: uuid('role_id')
      .notNull()
      .references(() => rolesTable.id, { onDelete: 'cascade' }),
  },
  (table) => [primaryKey({ columns: [table.userId, table.roleId] })],
);
