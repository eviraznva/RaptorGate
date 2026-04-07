import { isoDateTimeSchema, tableFileSchema, uuidSchema } from "./_common.js";
import { z } from "zod";

export const ConfigurationSnapshotRecordSchema = z
	.object({
		id: uuidSchema,
		versionNumber: z.number().int(),
		snapshotType: z.string().min(1).max(32),
		checksum: z.string().min(1).max(128),
		isActive: z.boolean(),
		payloadJson: z.unknown(),
		changeSummary: z.string().nullable(),
		createdAt: isoDateTimeSchema,
		createdBy: uuidSchema,
	})
	.strict();

export const ConfigurationSnapshotsFileSchema = tableFileSchema(
	ConfigurationSnapshotRecordSchema,
);

export type ConfigurationSnapshotRecord = z.infer<
	typeof ConfigurationSnapshotRecordSchema
>;
export type ConfigurationSnapshotsFile = z.infer<
	typeof ConfigurationSnapshotsFileSchema
>;
