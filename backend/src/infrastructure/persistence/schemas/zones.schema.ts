import { z } from "zod";
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";

const defaultZoneIdSchema = z.literal("00000000-0000-0000-0000-000000000000");
const zoneIdSchema = z.union([uuidSchema, defaultZoneIdSchema]);

export const ZoneRecordSchema = z
  .object({
    id: zoneIdSchema,
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
