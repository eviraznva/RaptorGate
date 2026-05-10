import { describe, expect, it, jest } from '@jest/globals';
import type { ClientGrpc } from '@nestjs/microservices';
import { of } from 'rxjs';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { NatRule } from '../../domain/entities/nat-rule.entity.js';
import { NatConfigIsInvalidException } from '../../domain/exceptions/nat-config-is-invalid.exception.js';
import { Checksum } from '../../domain/value-objects/checksum.vo.js';
import { Priority } from '../../domain/value-objects/priority.vo.js';
import { SnapshotType } from '../../domain/value-objects/snapshot-type.vo.js';
import { NatProtocol } from '../grpc/generated/common/common.js';
import { GrpcConfigSnapshotPushService } from './grpc-config-snapshot-push.service.js';

function makeSnapshot(natRule: NatRule): ConfigurationSnapshot {
  return ConfigurationSnapshot.create(
    'f0870f37-8b24-4c08-bff0-90c4270f5858',
    1,
    SnapshotType.create('auto_save'),
    Checksum.create('a'.repeat(64)),
    true,
    {
      bundle: {
        rules: { items: [] },
        zones: { items: [] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [] },
        nat_rules: { items: [natRule] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [] },
        users: { items: [] },
      },
    },
    null,
    new Date('2026-03-20T23:11:43.970Z'),
    '8d3fae59-d1b7-4812-9f31-caf772a9252c',
  );
}

describe('GrpcConfigSnapshotPushService', () => {
  it('rejects NAT rule without action before gRPC push', async () => {
    const pushActiveConfigSnapshot = jest.fn(() => of({ accepted: true }));
    const service = new GrpcConfigSnapshotPushService({
      getService: () => ({
        pushActiveConfigSnapshot,
      }),
    } as unknown as ClientGrpc);
    service.onModuleInit();

    const natRule = NatRule.createSnatRule({
      id: '5d375e76-b212-4c9e-8da0-601e5ebb3cd3',
      isActive: true,
      priority: Priority.create(10),
      protocol: NatProtocol.NAT_PROTOCOL_ALL,
      createdAt: new Date('2026-03-20T23:11:43.970Z'),
      updatedAt: new Date('2026-03-20T23:11:43.970Z'),
      snat: {
        srcCidr: '192.168.1.10/32',
        translatedIp: '198.51.100.10',
      },
    });
    (natRule as unknown as { action: undefined }).action = undefined;

    await expect(
      service.pushActiveConfigSnapshot(makeSnapshot(natRule), 'apply'),
    ).rejects.toBeInstanceOf(NatConfigIsInvalidException);
    expect(pushActiveConfigSnapshot).not.toHaveBeenCalled();
  });
});
