import { RegexPattern } from "src/domain/value-objects/regex-pattern.vo.js";
import { z } from "zod";
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";

export const IpsSignatureRecordSchema = z
  .object({
    id: uuidSchema,
    name: z.string().min(1).max(128),
    isActive: z.boolean(),
    category: z.string().min(1).max(32),

    pattern: z.string().refine(
      (val) => {
        return RegexPattern.isValid(val);
      },
      { message: "Invalid regex pattern according to VO" },
    ),
    severity: z.string().min(1).max(16),
    action: z.string().min(1).max(16),
    appProtocols: z.array(z.string().min(1).max(32)).max(16),
    srcPorts: z.array(z.number().int().min(1).max(65535)).max(16),
    dstPorts: z.array(z.number().int().min(1).max(65535)).max(16),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict();

export const IpsSignaturesFileSchema = tableFileSchema(
  IpsSignatureRecordSchema,
);

export type IpsSignatureRecord = z.infer<typeof IpsSignatureRecordSchema>;
export type IpsSignaturesFile = z.infer<typeof IpsSignaturesFileSchema>;
