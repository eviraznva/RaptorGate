import {
  boolean,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';
import { defineRelations } from 'drizzle-orm';
import { usersTable } from './users.schema';

export const firewallCertificatesTable = pgTable('firewall_certificates', {
  id: uuid('id').primaryKey(),
  certType: varchar('cert_type', { length: 32 }).notNull(),
  commonName: varchar('common_name', { length: 255 }).notNull(),
  fingerprint: varchar('fingerprint', { length: 128 }).notNull(),
  certificatePem: text('certificate_pem').notNull(),
  privateKeyRef: varchar('private_key_ref', { length: 255 }).notNull(),
  isActive: boolean('is_active').notNull().default(true),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  createdBy: uuid('created_by')
    .notNull()
    .references(() => usersTable.id, { onDelete: 'no action' }),
});

export const firewallCertificateRelations = defineRelations(
  {
    usersTable,
    firewallCertificatesTable,
  },
  (r) => ({
    firewallCertificatesTable: {
      author: r.one.usersTable({
        from: r.firewallCertificatesTable.createdBy,
        to: r.usersTable.id,
      }),
    },
    usersTable: {
      certificates: r.many.firewallCertificatesTable(),
    },
  }),
);
