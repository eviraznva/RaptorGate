import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common.js';
import { z } from 'zod';

const defaultZoneIdSchema = z.literal('00000000-0000-0000-0000-000000000000');
const zonePairZoneIdSchema = z.union([uuidSchema, defaultZoneIdSchema]);

export const ZonePairRecordSchema = z
  .object({
    id: uuidSchema,
    srcZoneId: zonePairZoneIdSchema,
    dstZoneID: zonePairZoneIdSchema,
    defaultPolicy: z.string().min(1),
    createdAt: isoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const ZonePairsFileSchema = tableFileSchema(ZonePairRecordSchema);

export type ZonePairRecord = z.infer<typeof ZonePairRecordSchema>;
export type ZonePairsFile = z.infer<typeof ZonePairsFileSchema>;
