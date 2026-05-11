import z from "zod";
import { IpsSignatureRecordSchema } from "./ips-signatures.schema";

export const IpsConfigSchema = z
  .object({
    general: z
      .object({
        enabled: z.boolean(),
      })
      .strict(),
    detection: z
      .object({
        enabled: z.boolean(),
        maxPayloadBytes: z.number().int().min(1),
        maxMatchesPerPacket: z.number().int().min(1),
      })
      .strict(),
    signatures: z.array(IpsSignatureRecordSchema),
  })
  .strict();

export type IpsConfigRecord = z.infer<typeof IpsConfigSchema>;

export const defaultIpsConfig: IpsConfigRecord = {
  general: {
    enabled: false,
  },
  detection: {
    enabled: false,
    maxPayloadBytes: 8192,
    maxMatchesPerPacket: 10,
  },
  signatures: [
    {
      id: "7f4c2b9e-8d31-4a6f-b2c7-1e9d5f3a8c42",
      name: "Example SQLi Block",
      isActive: true,
      category: "sqli",
      pattern: "(?i)UNION\\s+SELECT",
      matchType: "IPS_MATCH_TYPE_REGEX",
      patternEncoding: "IPS_PATTERN_ENCODING_TEXT",
      caseInsensitive: false,
      severity: "SEVERITY_HIGH",
      action: "IPS_ACTION_BLOCK",
      appProtocols: ["IPS_APP_PROTOCOL_HTTP"],
      srcPorts: [],
      dstPorts: [80, 443],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    },
  ],
};
