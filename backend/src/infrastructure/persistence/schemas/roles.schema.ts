import { tableFileSchema, uuidSchema } from './_common.js';
import { z } from 'zod';

export const RoleRecordSchema = z
  .object({
    id: uuidSchema,
    name: z.string().min(1).max(64),
    description: z.string().max(255).nullable().optional(),
  })
  .strict();

export const RolesFileSchema = tableFileSchema(RoleRecordSchema);

export type RoleRecord = z.infer<typeof RoleRecordSchema>;
export type RolesFile = z.infer<typeof RolesFileSchema>;
