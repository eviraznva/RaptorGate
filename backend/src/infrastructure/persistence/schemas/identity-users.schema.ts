import { z } from 'zod';
import {
  isoDateTimeSchema,
  nullableIsoDateTimeSchema,
  tableFileSchema,
  uuidSchema,
} from './_common';

export const IdentityUserRecordSchema = z
  .object({
    id: uuidSchema,
    username: z.string().min(1).max(128),
    displayName: z.string().min(1).max(128),
    source: z.string().min(1).max(16),
    externalId: z.string().min(1).max(255),
    email: z.string().max(255).nullable().optional(),
    lastSeenAt: nullableIsoDateTimeSchema.optional(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict();

export const IdentityUsersFileSchema = tableFileSchema(IdentityUserRecordSchema);

export type IdentityUserRecord = z.infer<typeof IdentityUserRecordSchema>;
export type IdentityUsersFile = z.infer<typeof IdentityUsersFileSchema>;
