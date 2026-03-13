import { pgTable, timestamp, uuid, varchar } from 'drizzle-orm/pg-core';

export const identityUsersTable = pgTable('identity_users', {
  id: uuid('id').primaryKey(),
  username: varchar('username', { length: 128 }).notNull(),
  displayName: varchar('display_name', { length: 128 }).notNull(),
  source: varchar('source', { length: 16 }).notNull(),
  externalId: varchar('external_id', { length: 255 }).notNull(),
  email: varchar('email', { length: 255 }),
  lastSeenAt: timestamp('last_seen_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});
