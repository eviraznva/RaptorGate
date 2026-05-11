import { RegexPattern } from "src/domain/value-objects/regex-pattern.vo.js";
import { z } from "zod";
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";

export const SignatureSeveritySchema = z.enum([
  "SEVERITY_UNSPECIFIED",
  "SEVERITY_INFO",
  "SEVERITY_LOW",
  "SEVERITY_MEDIUM",
  "SEVERITY_HIGH",
  "SEVERITY_CRITICAL",
  "UNRECOGNIZED",
]);

export const IpsActionSchema = z.enum([
  "IPS_ACTION_UNSPECIFIED",
  "IPS_ACTION_ALERT",
  "IPS_ACTION_BLOCK",
  "UNRECOGNIZED",
]);

export const IpsMatchTypeSchema = z.enum([
  "IPS_MATCH_TYPE_LITERAL",
  "IPS_MATCH_TYPE_REGEX",
]);

export const IpsPatternEncodingSchema = z.enum([
  "IPS_PATTERN_ENCODING_TEXT",
  "IPS_PATTERN_ENCODING_HEX",
]);

function isValidHexPattern(pattern: string): boolean {
  const normalized = pattern.replace(/\s+/g, "");

  return normalized.length > 0 && normalized.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(normalized);
}

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
      { message: "Invalid IPS pattern" },
    ),
    matchType: IpsMatchTypeSchema.default("IPS_MATCH_TYPE_REGEX"),
    patternEncoding: IpsPatternEncodingSchema.default("IPS_PATTERN_ENCODING_TEXT"),
    caseInsensitive: z.boolean().default(false),
    severity: SignatureSeveritySchema,
    action: IpsActionSchema,
    appProtocols: z.array(z.string().min(1).max(32)).max(16),
    srcPorts: z.array(z.number().int().min(1).max(65535)).max(16),
    dstPorts: z.array(z.number().int().min(1).max(65535)).max(16),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict()
  .refine(
    (record) =>
      !(
        record.patternEncoding === "IPS_PATTERN_ENCODING_HEX" &&
        record.matchType === "IPS_MATCH_TYPE_REGEX"
      ),
    { message: "Hex encoded IPS signatures cannot use regex match type" },
  )
  .refine(
    (record) =>
      !(
        record.patternEncoding === "IPS_PATTERN_ENCODING_HEX" &&
        record.caseInsensitive
      ),
    { message: "Hex encoded IPS signatures cannot be case insensitive" },
  )
  .refine(
    (record) =>
      record.patternEncoding !== "IPS_PATTERN_ENCODING_HEX" ||
      isValidHexPattern(record.pattern),
    { message: "Hex encoded IPS signature pattern must contain whole bytes" },
  );

export const IpsSignaturesFileSchema = tableFileSchema(
  IpsSignatureRecordSchema,
);

export type IpsSignatureRecord = z.infer<typeof IpsSignatureRecordSchema>;
export type IpsSignaturesFile = z.infer<typeof IpsSignaturesFileSchema>;
