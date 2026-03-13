import { pgTable, timestamp, uuid, varchar } from 'drizzle-orm/pg-core';
import { identityUsersTable } from './identity-users.schema';
import { defineRelations } from 'drizzle-orm';

export const identityManagerUserSessionsTable = pgTable(
  'identity_manager_user_sessions',
  {
    id: uuid('id').primaryKey(),
    identityUserId: uuid('identity_user_id')
      .notNull()
      .references(() => identityUsersTable.id, { onDelete: 'no action' }),
    radiusUsername: varchar('radius_username', { length: 255 }).notNull(),
    macAddress: varchar('mac_address', { length: 45 }).notNull(),
    ipAddress: varchar('ip_address', { length: 45 }).notNull(),
    nasIp: varchar('nas_ip', { length: 64 }).notNull(),
    calledStationId: varchar('called_station_id', { length: 64 }).notNull(),
    authenticatedAt: timestamp('authenticated_at').notNull(),
    expiresAt: timestamp('expires_at').notNull(),
    syncedFromRedisAt: timestamp('synced_from_redis_at'),
  },
);

export const identityManagerUserSessionsRelations = defineRelations(
  {
    identityUsersTable,
    identityManagerUserSessionsTable,
  },
  (r) => ({
    identityManagerUserSessionsTable: {
      author: r.one.identityUsersTable({
        from: r.identityManagerUserSessionsTable.identityUserId,
        to: r.identityUsersTable.id,
      }),
    },
    identityUsersTable: {
      identityManagerUserSessions: r.many.identityManagerUserSessionsTable(),
    },
  }),
);
