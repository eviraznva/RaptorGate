import { defineRelations } from 'drizzle-orm';
import { pgTable, timestamp, uuid, varchar } from 'drizzle-orm/pg-core';
import { usersTable } from './users.schema';
import { zonesTable } from './zones.schema';

export const zonePairsTable = pgTable('zone_pairs', {
  id: uuid('id').primaryKey(),
  srcZoneId: uuid('src_zone_id')
    .notNull()
    .references(() => zonesTable.id, { onDelete: 'no action' }),
  dstZoneID: uuid('dst_zone_id')
    .notNull()
    .references(() => zonesTable.id, { onDelete: 'no action' }),
  defaultPolicy: varchar('default_policy').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const zonePairsRelations = defineRelations(
  {
    usersTable,
    zonesTable,
    zonePairsTable,
  },
  (r) => ({
    zonePairsTable: {
      author: r.one.usersTable({
        from: r.zonePairsTable.createdBy,
        to: r.usersTable.id,
      }),

      srcZone: r.one.zonesTable({
        from: r.zonePairsTable.srcZoneId,
        to: r.zonesTable.id,
        alias: 'src_zone',
      }),
      dstZone: r.one.zonesTable({
        from: r.zonePairsTable.dstZoneID,
        to: r.zonesTable.id,
        alias: 'dst_zone',
      }),
    },

    usersTable: {
      zonePairs: r.many.zonePairsTable(),
    },

    zonesTable: {
      zonePairsAsSrc: r.many.zonePairsTable({ alias: 'src_zone' }),
      zonePairsAsDst: r.many.zonePairsTable({ alias: 'dst_zone' }),
    },
  }),
);
