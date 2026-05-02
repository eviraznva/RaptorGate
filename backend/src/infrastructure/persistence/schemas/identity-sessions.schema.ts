import { z } from 'zod';
import { isoDateTimeSchema } from './_common.js';

export const IdentitySessionRecordSchema = z
  .object({
    id: z.string().min(1).max(128),
    identityUserId: z.string().min(1).max(512),
    username: z.string().min(1).max(256),
    sourceIp: z.string().min(1).max(64),
    createdAt: isoDateTimeSchema,
    expiresAt: isoDateTimeSchema,
    groups: z.array(z.string().min(1).max(256)),
    nasIp: z.string().min(1).max(64),
    calledStationId: z.string().min(1).max(256),
    macAddress: z.string().min(1).max(64),
  })
  .strict();

export const IdentitySessionsFileSchema = z
  .object({
    items: z.array(IdentitySessionRecordSchema),
  })
  .strict();

export type IdentitySessionRecord = z.infer<typeof IdentitySessionRecordSchema>;
export type IdentitySessionsFile = z.infer<typeof IdentitySessionsFileSchema>;
