import { pgTable, uuid, varchar } from 'drizzle-orm/pg-core';

export const permissionsTable = pgTable('permissions', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 128 }).notNull().unique(),
  description: varchar('description', { length: 255 }),
});
