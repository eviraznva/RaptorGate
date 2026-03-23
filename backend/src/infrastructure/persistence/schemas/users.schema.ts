import { z } from 'zod';
import {
  isoDateTimeSchema,
  nullableIsoDateTimeSchema,
  tableFileSchema,
  uuidSchema,
} from './_common';

export const UserRecordSchema = z
  .object({
    id: uuidSchema,
    username: z.string().min(1).max(64),
    passwordHash: z.string().min(1).max(255),
    refreshToken: z.string().nullable(),
    refreshTokenExpiry: nullableIsoDateTimeSchema,
    createdAt: isoDateTimeSchema,
    updatedAt: isoDateTimeSchema,
  })
  .strict();

export const UsersFileSchema = tableFileSchema(UserRecordSchema);

export type UserRecord = z.infer<typeof UserRecordSchema>;
export type UsersFile = z.infer<typeof UsersFileSchema>;
