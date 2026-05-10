import { of } from 'rxjs';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { Checksum } from '../../domain/value-objects/checksum.vo.js';
import { SnapshotType } from '../../domain/value-objects/snapshot-type.vo.js';
import { GrpcConfigSnapshotPushService } from './grpc-config-snapshot-push.service.js';

function methodObject(methods: Record<string, unknown>) {
  return methods;
}

describe('GrpcConfigSnapshotPushService', () => {
  it('serializes zone interface oneof in proto-loader shape', async () => {
    let request: any;
    const client = {
      getService: () => ({
        pushActiveConfigSnapshot: (value: any) => {
          request = value;
          return of({ accepted: true, appliedSnapshotId: value.snapshot.id });
        },
      }),
    } as any;
    const service = new GrpcConfigSnapshotPushService(client);
    service.onModuleInit();
    const zoneInterface = methodObject({
      getId: () => '55555555-5555-4555-8555-555555555555',
      getZoneId: () => '11111111-1111-4111-8111-111111111111',
      getVlanId: () => null,
      getInterfaceName: () => 'eth2',
      getStatus: () => 'active',
      getAddresses: () => ['192.168.20.254/24'],
      getSniffed: () => true,
      getParentInterfaceId: () => null,
    });
    const snapshot = ConfigurationSnapshot.create(
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      1,
      SnapshotType.create('auto_save'),
      Checksum.create('0'.repeat(64)),
      true,
      {
        bundle: {
          rules: { items: [] },
          zones: { items: [] },
          zone_interfaces: { items: [zoneInterface] },
          zone_pairs: { items: [] },
          nat_rules: { items: [] },
          dns_blacklist: { items: [] },
          ssl_bypass_list: { items: [] },
          ips_signatures: { items: [] },
          ml_model: null,
          firewall_certificates: { items: [] },
          tls_inspection_policy: undefined,
        },
      },
      'test',
      new Date('2026-05-09T00:00:00.000Z'),
      'tester',
    );

    await service.pushActiveConfigSnapshot(snapshot, 'apply');

    expect(request.snapshot.bundle.zoneInterfaces[0]).toMatchObject({
      id: '55555555-5555-4555-8555-555555555555',
      zoneId: '11111111-1111-4111-8111-111111111111',
      physical: { interfaceName: 'eth2' },
    });
    expect(request.snapshot.bundle.zoneInterfaces[0].kind).toBeUndefined();
  });
});
