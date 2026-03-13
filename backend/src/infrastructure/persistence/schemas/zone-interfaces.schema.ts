import { timestamp } from 'drizzle-orm/pg-core';
import { integer, varchar } from 'drizzle-orm/pg-core';
import { pgTable, uuid } from 'drizzle-orm/pg-core';
import { zonesTable } from './zones.schema';
import { defineRelations } from 'drizzle-orm';

export const zoneInterfacesTable = pgTable('zone_interfaces', {
  id: uuid('id').primaryKey(),
  zoneId: uuid('zone_id')
    .notNull()
    .references(() => zonesTable.id, { onDelete: 'no action' }),
  interfaceName: varchar('interface_name', { length: 64 }).notNull(),
  vlanId: integer().notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const zoneInterfacesRelations = defineRelations(
  {
    zonesTable,
    zoneInterfacesTable,
  },
  (r) => ({
    zoneInterfacesTable: {
      author: r.one.zonesTable({
        from: r.zoneInterfacesTable.zoneId,
        to: r.zonesTable.id,
      }),
    },

    zonesTable: {
      zoneInterfaces: r.many.zoneInterfacesTable(),
    },
  }),
);
