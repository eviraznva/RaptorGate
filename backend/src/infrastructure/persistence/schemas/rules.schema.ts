import { z } from "zod";
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";

const defaultZoneIdSchema = z.literal("00000000-0000-0000-0000-000000000000");
const zoneIdSchema = z.union([uuidSchema, defaultZoneIdSchema]);

export const RuleRecordSchema = z
  .object({
    id: uuidSchema,
    name: z.string().min(1).max(128),
    description: z.string().nullable().optional(),
    zonePairId: zoneIdSchema,
    isActive: z.boolean(),
    content: z.string().min(1),
    priority: z.number().int(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const RulesFileSchema = tableFileSchema(RuleRecordSchema);

export type RuleRecord = z.infer<typeof RuleRecordSchema>;
export type RulesFile = z.infer<typeof RulesFileSchema>;
