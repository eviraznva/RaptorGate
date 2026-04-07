import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";
import { z } from "zod";

export const DnsBlacklistRecordSchema = z
	.object({
		id: uuidSchema,
		domain: z.string().min(1).max(255),
		reason: z.string().min(1),
		isActive: z.boolean(),
		createdAt: isoDateTimeSchema,
		createdBy: uuidSchema,
	})
	.strict();

export const DnsBlacklistFileSchema = tableFileSchema(DnsBlacklistRecordSchema);

export type DnsBlacklistRecord = z.infer<typeof DnsBlacklistRecordSchema>;
export type DnsBlacklistFile = z.infer<typeof DnsBlacklistFileSchema>;
