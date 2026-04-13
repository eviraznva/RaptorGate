import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";
import { z } from "zod";

export const IpsSignatureRecordSchema = z
	.object({
		id: uuidSchema,
		name: z.string().min(1).max(128),
		category: z.string().min(1).max(32),
		pattern: z.string().min(1),
		severity: z.string().min(1).max(16),
		isActive: z.boolean(),
		createdAt: isoDateTimeSchema,
		updatedAt: isoDateTimeSchema,
	})
	.strict();

export const IpsSignaturesFileSchema = tableFileSchema(
	IpsSignatureRecordSchema,
);

export type IpsSignatureRecord = z.infer<typeof IpsSignatureRecordSchema>;
export type IpsSignaturesFile = z.infer<typeof IpsSignaturesFileSchema>;
