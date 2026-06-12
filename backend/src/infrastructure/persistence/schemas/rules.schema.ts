import { z } from "zod";
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";

const defaultZoneIdSchema = z.literal("00000000-0000-0000-0000-000000000000");
const zoneIdSchema = z.union([uuidSchema, defaultZoneIdSchema]);

const smtpMatchActionSchema = z.enum(["allow", "deny"]);

const smtpMatchSchema = z.object({
  regex: z.string().min(1),
  onMatch: smtpMatchActionSchema,
});

const smtpMatchersSchema = z.object({
  sender: z.array(smtpMatchSchema),
  recipient: z.array(smtpMatchSchema),
  message: z.array(smtpMatchSchema),
});

export type SmtpMatchers = z.infer<typeof smtpMatchersSchema>;

const sshMatchSchema = z.object({
  regex: z.string().min(1),
  onMatch: smtpMatchActionSchema,
});

const sshReasonMatchSchema = z.object({
  codes: z.array(z.number().int()),
  onMatch: smtpMatchActionSchema,
});

const sshMatchersSchema = z.object({
  clientSoftware: z.array(sshMatchSchema),
  serverSoftware: z.array(sshMatchSchema),
  clientProtoVersion: z.array(sshMatchSchema),
  serverProtoVersion: z.array(sshMatchSchema),
  kex: z.array(sshMatchSchema),
  hostKeyAlg: z.array(sshMatchSchema),
  cipher: z.array(sshMatchSchema),
  mac: z.array(sshMatchSchema),
  compression: z.array(sshMatchSchema),
  hostKeyType: z.array(sshMatchSchema),
  disconnectReason: z.array(sshReasonMatchSchema),
});

export type SshMatchers = z.infer<typeof sshMatchersSchema>;

const emptySshMatchers = {
  clientSoftware: [],
  serverSoftware: [],
  clientProtoVersion: [],
  serverProtoVersion: [],
  kex: [],
  hostKeyAlg: [],
  cipher: [],
  mac: [],
  compression: [],
  hostKeyType: [],
  disconnectReason: [],
};

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
    smtpMatchers: smtpMatchersSchema.default({
      sender: [],
      recipient: [],
      message: [],
    }),
    sshMatchers: sshMatchersSchema.default(emptySshMatchers),
  })
  .strict();

export const RulesFileSchema = tableFileSchema(RuleRecordSchema);

export type RuleRecord = z.infer<typeof RuleRecordSchema>;
export type RulesFile = z.infer<typeof RulesFileSchema>;
