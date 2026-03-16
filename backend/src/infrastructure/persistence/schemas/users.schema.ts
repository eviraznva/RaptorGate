import { pgEnum, pgTable, timestamp, uuid, varchar } from 'drizzle-orm/pg-core';
import { Role } from '../../../domain/enums/role.enum';

export const roleEnum = pgEnum('user_roles', [
  Role.SuperAdmin,
  Role.Admin,
  Role.Operator,
  Role.Viewer,
]);

export const usersTable = pgTable('users', {
  id: uuid('id').primaryKey(),
  username: varchar('username', { length: 64 }).notNull(),
  passwordHash: varchar('password_hash', { length: 255 }).notNull(),
  refreshToken: varchar('refresh_token'),
  refreshTokenExpiry: timestamp('refresh_token_expiry'),
  role: roleEnum('role').notNull().default(Role.Viewer),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});
