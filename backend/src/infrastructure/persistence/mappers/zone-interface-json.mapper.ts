import { ZoneInterface } from '../../../domain/entities/zone-interface.entity.js';
import { ZoneInterfaceRecord } from '../schemas/zone-interfaces.schema.js';

export class ZoneInterfaceJsonMapper {
  static toDomain(record: ZoneInterfaceRecord): ZoneInterface {
    return ZoneInterface.create(
      record.id,
      record.zoneId,
      record.interfaceName,
      record.vlanId,
      new Date(record.createdAt),
    );
  }

  static toRecord(zoneInterface: ZoneInterface): ZoneInterfaceRecord {
    return {
      id: zoneInterface.getId(),
      zoneId: zoneInterface.getZoneId(),
      interfaceName: zoneInterface.getInterfaceName(),
      vlanId: zoneInterface.getVlanId(),
      createdAt: zoneInterface.getCreatedAt().toISOString(),
    };
  }
}
