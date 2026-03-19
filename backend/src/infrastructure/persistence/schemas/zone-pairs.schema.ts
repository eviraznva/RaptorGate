import { z } from 'zod';
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common';

export const ZonePairRecordSchema = z
  .object({
    id: uuidSchema,
    srcZoneId: uuidSchema,
    dstZoneID: uuidSchema,
    defaultPolicy: z.string().min(1),
    createdAt: isoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const ZonePairsFileSchema = tableFileSchema(ZonePairRecordSchema);

export type ZonePairRecord = z.infer<typeof ZonePairRecordSchema>;
export type ZonePairsFile = z.infer<typeof ZonePairsFileSchema>;
