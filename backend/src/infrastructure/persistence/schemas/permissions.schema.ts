import { z } from 'zod';
import { tableFileSchema, uuidSchema } from './_common';

export const PermissionRecordSchema = z
  .object({
    id: uuidSchema,
    name: z.string().min(1).max(128),
    description: z.string().max(255).nullable().optional(),
  })
  .strict();

export const PermissionsFileSchema = tableFileSchema(PermissionRecordSchema);

export type PermissionRecord = z.infer<typeof PermissionRecordSchema>;
export type PermissionsFile = z.infer<typeof PermissionsFileSchema>;
