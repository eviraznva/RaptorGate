import { isoDateTimeSchema } from './_common.js';
import { z } from 'zod';

export const MetaSchema = z
  .object({
    schemaVersion: z.number().int().nonnegative(),
    generatedAt: isoDateTimeSchema,
    seed: z.record(z.string(), z.number().int().nonnegative()).optional(),
    notes: z.string().optional(),
  })
  .strict();

export type Meta = z.infer<typeof MetaSchema>;
