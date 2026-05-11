import { isoDateTimeSchema } from './_common.js';
import { z } from 'zod';

export const AdminAuthSessionRecordSchema = z
  .object({
    id: z.string().min(1).max(128),
    username: z.string().min(1).max(256),
    provider: z.enum(['radius', 'ldap']),
    authProfileId: z.string().min(1).max(128),
    externalId: z.string().min(1).max(512),
    roles: z.array(z.enum(['super_admin', 'admin', 'operator', 'viewer'])).min(1),
    refreshTokenHash: z.string().min(1).max(256),
    refreshTokenExpiry: isoDateTimeSchema,
    createdAt: isoDateTimeSchema,
    lastSeenAt: isoDateTimeSchema,
    revokedAt: isoDateTimeSchema.nullable(),
  })
  .strict();

export const AdminAuthSessionsFileSchema = z
  .object({
    items: z.array(AdminAuthSessionRecordSchema),
  })
  .strict();

export type AdminAuthSessionRecord = z.infer<
  typeof AdminAuthSessionRecordSchema
>;
export type AdminAuthSessionsFile = z.infer<
  typeof AdminAuthSessionsFileSchema
>;
