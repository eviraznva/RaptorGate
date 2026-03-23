import { z } from 'zod';
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common';

export const NatRuleRecordSchema = z
  .object({
    id: uuidSchema,
    type: z.string().min(1).max(16),
    isActive: z.boolean(),
    srcIp: z.string().max(64).nullable().optional(),
    dstIp: z.string().max(64).nullable().optional(),
    srcPort: z.number().int().nullable().optional(),
    dstPort: z.number().int().nullable().optional(),
    translatedIp: z.string().max(64).nullable().optional(),
    translatedPort: z.number().int().nullable().optional(),
    priority: z.number().int(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const NatRulesFileSchema = tableFileSchema(NatRuleRecordSchema);

export type NatRuleRecord = z.infer<typeof NatRuleRecordSchema>;
export type NatRulesFile = z.infer<typeof NatRulesFileSchema>;
