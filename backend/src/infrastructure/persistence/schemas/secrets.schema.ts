import { z } from 'zod';
import { SECRET_REF_PATTERN } from '../../../domain/value-objects/secret-ref.vo.js';
import { isoDateTimeSchema, tableFileSchema } from './_common.js';

export const SecretRecordSchema = z
  .object({
    ref: z.string().regex(SECRET_REF_PATTERN).refine((value) => value.startsWith('secret://')),
    ciphertext: z.string().min(1),
    iv: z.string().min(1),
    authTag: z.string().min(1),
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
    updatedBy: z.string().min(1).max(128),
  })
  .strict();

export const SecretsFileSchema = tableFileSchema(SecretRecordSchema);

export type SecretRecordJson = z.infer<typeof SecretRecordSchema>;
export type SecretsFile = z.infer<typeof SecretsFileSchema>;
