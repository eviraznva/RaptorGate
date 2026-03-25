import { z } from 'zod';
import {
  isoDateTimeSchema,
  nullableIsoDateTimeSchema,
  tableFileSchema,
  uuidSchema,
} from './_common';

export const IdentityManagerUserSessionRecordSchema = z
  .object({
    id: uuidSchema,
    identityUserId: uuidSchema,
    radiusUsername: z.string().min(1).max(255),
    macAddress: z.string().min(1).max(45),
    ipAddress: z.string().min(1).max(45),
    nasIp: z.string().min(1).max(64),
    calledStationId: z.string().min(1).max(64),
    authenticatedAt: isoDateTimeSchema,
    expiresAt: isoDateTimeSchema,
    syncedFromRedisAt: nullableIsoDateTimeSchema.optional(),
  })
  .strict();

export const IdentityManagerUserSessionsFileSchema = tableFileSchema(
  IdentityManagerUserSessionRecordSchema,
);

export type IdentityManagerUserSessionRecord = z.infer<
  typeof IdentityManagerUserSessionRecordSchema
>;
export type IdentityManagerUserSessionsFile = z.infer<
  typeof IdentityManagerUserSessionsFileSchema
>;
