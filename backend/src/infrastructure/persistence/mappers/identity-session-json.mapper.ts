import { IdentitySession } from '../../../domain/entities/identity-session.entity.js';
import { IpAddress } from '../../../domain/value-objects/ip-address.vo.js';
import type { IdentitySessionRecord } from '../schemas/identity-sessions.schema.js';

export class IdentitySessionJsonMapper {
  static toRecord(session: IdentitySession): IdentitySessionRecord {
    return {
      id: session.getId(),
      identityUserId: session.getIdentityUserId(),
      username: session.getUsername(),
      sourceIp: session.getSourceIp().getValue,
      createdAt: session.getCreatedAt().toISOString(),
      expiresAt: session.getExpiresAt().toISOString(),
      groups: session.getGroups(),
      nasIp: session.getNasIp(),
      calledStationId: session.getCalledStationId(),
      macAddress: session.getMacAddress(),
    };
  }

  static toDomain(record: IdentitySessionRecord): IdentitySession {
    return IdentitySession.create(
      record.id,
      record.username,
      IpAddress.create(record.sourceIp),
      new Date(record.createdAt),
      new Date(record.expiresAt),
      record.groups,
      record.nasIp,
      record.calledStationId,
      record.identityUserId,
      record.macAddress,
    );
  }
}
