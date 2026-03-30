import {
  isoDateTimeSchema,
  nullableIsoDateTimeSchema,
  tableFileSchema,
  uuidSchema,
} from './_common.js';
import { z } from 'zod';

export const MlModelRecordSchema = z
  .object({
    id: uuidSchema,
    name: z.string().min(1).max(128),
    version: z.string().min(1).max(64),
    artifactPath: z.string().min(1).max(255),
    checksum: z.string().min(1).max(128),
    isActive: z.boolean(),
    createdAt: isoDateTimeSchema,
    activatedAt: nullableIsoDateTimeSchema,
    createdBy: uuidSchema,
  })
  .strict();

export const MlModelsFileSchema = tableFileSchema(MlModelRecordSchema);

export type MlModelRecord = z.infer<typeof MlModelRecordSchema>;
export type MlModelsFile = z.infer<typeof MlModelsFileSchema>;
