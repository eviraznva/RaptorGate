import {
	isoDateTimeSchema,
	nullableIsoDateTimeSchema,
	tableFileSchema,
	uuidSchema,
} from "./_common.js";
import { z } from "zod";

export const SessionRecordSchema = z
	.object({
		id: uuidSchema,
		userId: uuidSchema,
		ipAddress: z.string().min(1).max(45),
		userAgent: z.string().min(1).max(255),
		isActive: z.boolean(),
		createdAt: isoDateTimeSchema,
		expiresAt: isoDateTimeSchema,
		revokedAt: nullableIsoDateTimeSchema.optional(),
	})
	.strict();

export const SessionsFileSchema = tableFileSchema(SessionRecordSchema);

export type SessionRecord = z.infer<typeof SessionRecordSchema>;
export type SessionsFile = z.infer<typeof SessionsFileSchema>;
