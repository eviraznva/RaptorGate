import { z } from 'zod';

export const uuidSchema = z.uuid({ version: 'v4' });
export const isoDateTimeSchema = z.iso.datetime({ offset: true });
export const nullableIsoDateTimeSchema = isoDateTimeSchema.nullable();

export const bigintLikeSchema = z.union([
  z.bigint(),
  z.number().int(),
  z.string().regex(/^-?\d+$/),
]);

export const tableFileSchema = <T extends z.ZodTypeAny>(itemSchema: T) =>
  z
    .object({
      items: z.array(itemSchema),
    })
    .strict();
