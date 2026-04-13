import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common.js';
import { z } from 'zod';

export const FirewallCertificateRecordSchema = z
  .object({
    id: uuidSchema,
    certType: z.string().min(1).max(32),
    commonName: z.string().min(1).max(255),
    fingerprint: z.string().min(1).max(128),
    certificatePem: z.string().min(1),
    privateKeyRef: z.string().min(1).max(255),
    isActive: z.boolean(),
    expiresAt: isoDateTimeSchema,
    createdAt: isoDateTimeSchema,
    createdBy: uuidSchema,
    bindAddress: z.string().max(255).default(''),
    bindPort: z.number().int().min(0).max(65535).default(443),
    inspectionBypass: z.boolean().default(false),
  })
  .strict();

export const FirewallCertificatesFileSchema = tableFileSchema(
  FirewallCertificateRecordSchema,
);

export type FirewallCertificateRecord = z.infer<
  typeof FirewallCertificateRecordSchema
>;
export type FirewallCertificatesFile = z.infer<
  typeof FirewallCertificatesFileSchema
>;
