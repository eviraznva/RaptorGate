import { z } from 'zod';
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common.js';

const portSchema = z.number().int().min(1).max(65535);

export const NatProtocolRecordSchema = z.enum([
  'NAT_PROTOCOL_ALL',
  'NAT_PROTOCOL_TCP',
  'NAT_PROTOCOL_UDP',
  'NAT_PROTOCOL_ICMP',
]);

const snatActionSchema = z.object({
  srcCidr: z.string().min(1).max(128),
  translatedIp: z.string().min(1).max(64),
  srcPortMin: portSchema.nullable().optional(),
  srcPortMax: portSchema.nullable().optional(),
});

const dnatActionSchema = z.object({
  dstCidr: z.string().min(1).max(128),
  translatedIp: z.string().min(1).max(64),
});

const patActionSchema = z.object({
  dstIp: z.string().min(1).max(64),
  dstPort: portSchema,
  translatedIp: z.string().min(1).max(64),
  translatedPort: portSchema,
});

const masqueradeActionSchema = z.object({
  srcCidr: z.string().min(1).max(128).nullable().optional(),
  srcPortMin: portSchema.nullable().optional(),
  srcPortMax: portSchema.nullable().optional(),
});

export const NatRuleActionRecordSchema = z.discriminatedUnion('$case', [
  z.object({ $case: z.literal('snat'), snat: snatActionSchema }),
  z.object({ $case: z.literal('dnat'), dnat: dnatActionSchema }),
  z.object({ $case: z.literal('pat'), pat: patActionSchema }),
  z.object({ $case: z.literal('masquerade'), masquerade: masqueradeActionSchema }),
]);

export const ProtoNatRuleRecordSchema = z
  .object({
    id: uuidSchema,
    isActive: z.boolean(),
    priority: z.number().int(),
    protocol: NatProtocolRecordSchema,
    inInterface: z.string().max(128).nullable().optional(),
    outInterface: z.string().max(128).nullable().optional(),
    inZone: z.string().max(128).nullable().optional(),
    outZone: z.string().max(128).nullable().optional(),
    matchSrcPortMin: portSchema.nullable().optional(),
    matchSrcPortMax: portSchema.nullable().optional(),
    matchDstPortMin: portSchema.nullable().optional(),
    matchDstPortMax: portSchema.nullable().optional(),
    action: NatRuleActionRecordSchema,
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const LegacyNatRuleRecordSchema = z
  .object({
    id: uuidSchema,
    type: z.string().min(1).max(16),
    isActive: z.boolean(),
    srcIp: z.string().max(64).nullable().optional(),
    dstIp: z.string().max(64).nullable().optional(),
    srcPort: portSchema.nullable().optional(),
    dstPort: portSchema.nullable().optional(),
    translatedIp: z.string().max(64).nullable().optional(),
    translatedPort: portSchema.nullable().optional(),
    priority: z.number().int(),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const NatRuleRecordSchema = z.union([
  ProtoNatRuleRecordSchema,
  LegacyNatRuleRecordSchema,
]);

export const NatRulesFileSchema = tableFileSchema(NatRuleRecordSchema);

export type ProtoNatRuleRecord = z.infer<typeof ProtoNatRuleRecordSchema>;
export type NatRuleRecord = z.infer<typeof NatRuleRecordSchema>;
export type NatRulesFile = z.infer<typeof NatRulesFileSchema>;
