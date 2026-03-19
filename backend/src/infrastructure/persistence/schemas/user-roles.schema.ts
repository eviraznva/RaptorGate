import { z } from 'zod';
import { tableFileSchema, uuidSchema } from './_common';

export const UserRoleRecordSchema = z
  .object({
    userId: uuidSchema,
    roleId: uuidSchema,
  })
  .strict();

export const UserRolesFileSchema = tableFileSchema(UserRoleRecordSchema);

export type UserRoleRecord = z.infer<typeof UserRoleRecordSchema>;
export type UserRolesFile = z.infer<typeof UserRolesFileSchema>;
