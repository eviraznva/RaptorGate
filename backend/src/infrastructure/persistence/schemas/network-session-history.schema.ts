import { z } from 'zod';
import {
  bigintLikeSchema,
  isoDateTimeSchema,
  nullableIsoDateTimeSchema,
  tableFileSchema,
  uuidSchema,
} from './_common';

export const NetworkSessionHistoryRecordSchema = z
  .object({
    id: uuidSchema,
    identitySessionId: uuidSchema,
    srcIp: z.string().min(1).max(45),
    dstIp: z.string().min(1).max(45),
    application: z.string().min(1).max(64),
    domain: z.string().min(1).max(255),
    bytesSent: bigintLikeSchema,
    bytesReceived: bigintLikeSchema,
    packetsTotal: bigintLikeSchema,
    startedAt: isoDateTimeSchema,
    endedAt: nullableIsoDateTimeSchema.optional(),
  })
  .strict();

export const NetworkSessionHistoryFileSchema = tableFileSchema(
  NetworkSessionHistoryRecordSchema,
);

export type NetworkSessionHistoryRecord = z.infer<
  typeof NetworkSessionHistoryRecordSchema
>;
export type NetworkSessionHistoryFile = z.infer<
  typeof NetworkSessionHistoryFileSchema
>;
