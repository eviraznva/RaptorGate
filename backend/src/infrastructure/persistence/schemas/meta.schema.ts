import { z } from 'zod';
import { isoDateTimeSchema } from './_common';

export const MetaSchema = z
  .object({
    schemaVersion: z.number().int().nonnegative(),
    generatedAt: isoDateTimeSchema,
    seed: z.record(z.string(), z.number().int().nonnegative()).optional(),
    notes: z.string().optional(),
  })
  .strict();

export type Meta = z.infer<typeof MetaSchema>;
