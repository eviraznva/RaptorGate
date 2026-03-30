import { tableFileSchema, uuidSchema } from './_common.js';
import { z } from 'zod';

export const RolePermissionRecordSchema = z
  .object({
    roleId: uuidSchema,
    permissionId: uuidSchema,
  })
  .strict();

export const RolePermissionsFileSchema = tableFileSchema(
  RolePermissionRecordSchema,
);

export type RolePermissionRecord = z.infer<typeof RolePermissionRecordSchema>;
export type RolePermissionsFile = z.infer<typeof RolePermissionsFileSchema>;
