import { isoDateTimeSchema, tableFileSchema } from './_common.js';
import { z } from 'zod';

const zoneInterfaceIdSchema = z.uuid();
const noZoneIdSchema = z.literal('00000000-0000-0000-0000-000000000000');
const zoneInterfaceZoneIdSchema = z.union([
  zoneInterfaceIdSchema,
  noZoneIdSchema,
]);

export const ZoneInterfaceRecordSchema = z
  .object({
    id: zoneInterfaceIdSchema,
    zoneId: zoneInterfaceZoneIdSchema,
    interfaceName: z.string().min(1).max(64),
    vlanId: z.number().int().nullable(),
    status: z.enum(['unspecified', 'active', 'inactive', 'missing', 'unknown']),
    addresses: z.array(z.string()),
    createdAt: isoDateTimeSchema,
  })
  .strict();

export const ZoneInterfacesFileSchema = tableFileSchema(
  ZoneInterfaceRecordSchema,
);

export type ZoneInterfaceRecord = z.infer<typeof ZoneInterfaceRecordSchema>;
export type ZoneInterfacesFile = z.infer<typeof ZoneInterfacesFileSchema>;
