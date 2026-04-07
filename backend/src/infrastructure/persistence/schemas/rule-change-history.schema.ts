import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";
import { z } from "zod";

export const RuleChangeHistoryRecordSchema = z
	.object({
		id: uuidSchema,
		ruleId: uuidSchema,
		changedBy: uuidSchema,
		modifiedAt: isoDateTimeSchema,
		content: z.string().min(1),
	})
	.strict();

export const RuleChangeHistoryFileSchema = tableFileSchema(
	RuleChangeHistoryRecordSchema,
);

export type RuleChangeHistoryRecord = z.infer<
	typeof RuleChangeHistoryRecordSchema
>;
export type RuleChangeHistoryFile = z.infer<typeof RuleChangeHistoryFileSchema>;
