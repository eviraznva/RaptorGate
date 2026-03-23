import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common';
import { z } from 'zod';

export const ZoneRecordSchema = z
  .object({
    id: uuidSchema,
    name: z.string().min(1).max(64),
    description: z.string().nullable().optional(),
    isActive: z.boolean(),
    createdAt: isoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const ZonesFileSchema = tableFileSchema(ZoneRecordSchema);

export type ZoneRecord = z.infer<typeof ZoneRecordSchema>;
export type ZonesFile = z.infer<typeof ZonesFileSchema>;
