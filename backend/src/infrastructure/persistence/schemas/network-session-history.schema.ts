import { defineRelations } from 'drizzle-orm';
import { identityManagerUserSessionsTable } from './identity-manager-user-sessions.schema';
import { pgTable, uuid } from 'drizzle-orm/pg-core';
import { varchar } from 'drizzle-orm/pg-core';
import { bigint } from 'drizzle-orm/pg-core';
import { timestamp } from 'drizzle-orm/pg-core';

export const networkSessionHistoryTable = pgTable('network_session_history', {
  id: uuid('id').primaryKey(),
  identitySessionId: uuid('identity_session_id')
    .notNull()
    .references(() => identityManagerUserSessionsTable.id, {
      onDelete: 'no action',
    }),
  srcIp: varchar('src_ip', { length: 45 }).notNull(),
  dstIp: varchar('dst_ip', { length: 45 }).notNull(),
  application: varchar('application', { length: 64 }).notNull(),
  domain: varchar('domain', { length: 255 }).notNull(),
  bytesSent: bigint({ mode: 'bigint' }).notNull(),
  bytesReceived: bigint({ mode: 'bigint' }).notNull(),
  packetsTotal: bigint({ mode: 'bigint' }).notNull(),
  startedAt: timestamp('started_at').notNull(),
  endedAt: timestamp('ended_at'),
});

export const networkSessionHistoryRelations = defineRelations(
  {
    identityManagerUserSessionsTable,
    networkSessionHistoryTable,
  },
  (r) => ({
    networkSessionHistoryTable: {
      author: r.one.identityManagerUserSessionsTable({
        from: r.networkSessionHistoryTable.identitySessionId,
        to: r.identityManagerUserSessionsTable.id,
      }),
    },

    identityManagerUserSessionsTable: {
      networkSessionHistory: r.many.networkSessionHistoryTable(),
    },
  }),
);
