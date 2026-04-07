import { tableFileSchema, uuidSchema } from "./_common.js";
import { z } from "zod";

export const UserRoleRecordSchema = z
	.object({
		userId: uuidSchema,
		roleId: uuidSchema,
	})
	.strict();

export const UserRolesFileSchema = tableFileSchema(UserRoleRecordSchema);

export type UserRoleRecord = z.infer<typeof UserRoleRecordSchema>;
export type UserRolesFile = z.infer<typeof UserRolesFileSchema>;
