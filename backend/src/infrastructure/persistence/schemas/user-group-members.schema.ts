import { z } from 'zod';
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common';

export const UserGroupMemberRecordSchema = z
  .object({
    id: uuidSchema,
    groupId: uuidSchema,
    identityUserId: uuidSchema,
    joinedAt: isoDateTimeSchema,
  })
  .strict();

export const UserGroupMembersFileSchema = tableFileSchema(
  UserGroupMemberRecordSchema,
);

export type UserGroupMemberRecord = z.infer<typeof UserGroupMemberRecordSchema>;
export type UserGroupMembersFile = z.infer<typeof UserGroupMembersFileSchema>;
