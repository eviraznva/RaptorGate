import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";
import { z } from "zod";

export const UserGroupRecordSchema = z
	.object({
		id: uuidSchema,
		name: z.string().min(1).max(64),
		description: z.string().nullable().optional(),
		source: z.string().min(1).max(16),
		createdAt: isoDateTimeSchema,
		createdBy: uuidSchema,
	})
	.strict();

export const UserGroupsFileSchema = tableFileSchema(UserGroupRecordSchema);

export type UserGroupRecord = z.infer<typeof UserGroupRecordSchema>;
export type UserGroupsFile = z.infer<typeof UserGroupsFileSchema>;
