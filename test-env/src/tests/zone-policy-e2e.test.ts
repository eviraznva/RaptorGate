import { describe, test, beforeAll } from 'bun:test';
import '../harness';
import {
  request,
  resetFirewallState,
  getClient,
  getSnapshotClient,
  performCommand,
} from '../harness';
import { DefaultPolicy } from '../generated/common/common';
import { createDefaultSnapshotBundle } from '../harness/fixtures';

describe('Zone Policy E2E', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient(), getSnapshotClient());
  });

  test('ICMP allow_warn, TCP/UDP drop_warn between zone1 and zone2', async () => {
    const zone1Id = crypto.randomUUID();
    const zone2Id = crypto.randomUUID();
    const zonePairId = crypto.randomUUID();
    const zi1Id = crypto.randomUUID();
    const zi2Id = crypto.randomUUID();

    const bundle = createDefaultSnapshotBundle({
      zones: [
        { id: zone1Id, name: 'zone1', interfaceIds: [zi1Id] },
        { id: zone2Id, name: 'zone2', interfaceIds: [zi2Id] },
      ],
      zoneInterfaces: [
        { id: zi1Id, zoneId: zone1Id, interfaceName: 'eth1', status: 0, addresses: [] },
        { id: zi2Id, zoneId: zone2Id, interfaceName: 'eth2', status: 0, addresses: [] },
      ],
      zonePairs: [
        {
          id: zonePairId,
          srcZoneId: zone1Id,
          dstZoneId: zone2Id,
          defaultPolicy: DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED,
        },
      ],
      rules: [
        {
          id: crypto.randomUUID(),
          name: 'zone1-to-zone2-policy',
          zonePairId: zonePairId,
          priority: 0,
          content: `
            match protocol {
              =icmp: verdict allow_warn "icmp allowed"
              =tcp: verdict drop_warn "tcp dropped"
              =udp: verdict drop_warn "udp dropped"
            }
          `,
        },
      ],
    });

    await request('PushActiveConfigSnapshot', {
      correlationId: crypto.randomUUID(),
      reason: 'apply e2e zone policy',
      snapshot: {
        id: crypto.randomUUID(),
        versionNumber: 1,
        snapshotType: 'manual_import',
        checksum: 'zone-policy-e2e-checksum',
        isActive: true,
        changesSummary: 'zone-based policy for e2e test',
        createdAt: new Date(),
        createdBy: 'test-env',
        bundle,
      },
    }).run();

    // ICMP should be allowed with warning
    await performCommand({
      host: 'h1',
      command: 'ping -c 1 -W 1 192.168.20.10',
    })
      .expectEvents([
        { kind: 'policyWarning', match: { message: 'icmp allowed', verdict: 'allow' } },
      ])
      .expectOutput([/1 packets transmitted, 1 received/])
      .isOk()
      .run();

    // TCP should be dropped with warning
    const ncatServer = await performCommand({
      host: 'h2',
      command: 'ncat -l 4444',
    }).runDetached();

    try {
      await performCommand({
        host: 'h1',
        command: 'ncat -w 1 192.168.20.10 4444',
      })
        .expectEvents([
          { kind: 'policyWarning', match: { message: 'tcp dropped', verdict: 'drop' } },
        ])
        .isErr()
        .run();
    } finally {
      await ncatServer.kill();
    }

    // UDP should be dropped with warning
    await performCommand({
      host: 'h1',
      command: 'nc -u -z -w 1 192.168.20.10 5555',
    })
      .expectEvents([
        { kind: 'policyWarning', match: { message: 'udp dropped', verdict: 'drop' } },
      ])
      .isErr()
      .run();
  });
});
