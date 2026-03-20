import { z } from 'zod';
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common';

export const ZoneInterfaceRecordSchema = z
  .object({
    id: uuidSchema,
    zoneId: uuidSchema,
    interfaceName: z.string().min(1).max(64),
    vlanId: z.number().int(),
    createdAt: isoDateTimeSchema,
  })
  .strict();

export const ZoneInterfacesFileSchema = tableFileSchema(ZoneInterfaceRecordSchema);

export type ZoneInterfaceRecord = z.infer<typeof ZoneInterfaceRecordSchema>;
export type ZoneInterfacesFile = z.infer<typeof ZoneInterfacesFileSchema>;
