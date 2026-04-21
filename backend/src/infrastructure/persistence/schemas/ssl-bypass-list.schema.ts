import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common.js';
import { z } from 'zod';

export const SslBypassRecordSchema = z
  .object({
    id: uuidSchema,
    domain: z.string().min(1).max(255),
    reason: z.string().min(1),
    isActive: z.boolean(),
    createdAt: isoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const SslBypassListFileSchema = tableFileSchema(SslBypassRecordSchema);

export type SslBypassRecord = z.infer<typeof SslBypassRecordSchema>;
export type SslBypassListFile = z.infer<typeof SslBypassListFileSchema>;
