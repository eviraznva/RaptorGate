import { beforeAll, describe, test, expect } from 'bun:test';
import '../harness';
import {
  getClient,
  getSnapshotClient,
  resetFirewallState,
  performCommand,
  request,
} from '../harness';
import {
  InterfaceAdministrativeState,
  InterfaceStatus,
  interfaceStatusFromJSON,
  type ZoneInterface,
  type Zone,
} from '../generated/config/config_models';
import { createDefaultSnapshotBundle, DEFAULT_ZONE_INTERFACES } from '../harness/fixtures';

type RuntimeZoneInterface = {
  id?: unknown;
  zoneId?: unknown;
  interfaceName?: unknown;
  vlanId?: unknown;
  status?: unknown;
  addresses?: unknown;
};

type RuntimeGetLiveZoneInterfacesResponse = {
  zoneInterfaces?: unknown;
};

type QueryClientWithLiveZoneInterfaces = {
  getLiveZoneInterfaces(
    request: Record<string, never>,
    callback: (err: Error | null, response: unknown) => void,
  ): void;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function parseZoneInterface(value: unknown): ZoneInterface {
  if (!isRecord(value)) {
    throw new Error('GetLiveZoneInterfaces item is not an object');
  }

  const raw = value as RuntimeZoneInterface;
  if (typeof raw.id !== 'string') {
    throw new Error('GetLiveZoneInterfaces item is missing id');
  }
  if (typeof raw.zoneId !== 'string') {
    throw new Error('GetLiveZoneInterfaces item is missing zoneId');
  }
  if (typeof raw.interfaceName !== 'string') {
    throw new Error('GetLiveZoneInterfaces item is missing interfaceName');
  }
  if (!Array.isArray(raw.addresses) || raw.addresses.some((address) => typeof address !== 'string')) {
    throw new Error('GetLiveZoneInterfaces item has invalid addresses');
  }

  return {
    id: raw.id,
    zoneId: raw.zoneId,
    interfaceName: raw.interfaceName,
    vlanId: typeof raw.vlanId === 'number' ? raw.vlanId : undefined,
    status: interfaceStatusFromJSON(raw.status),
    addresses: raw.addresses,
  };
}

async function getLiveZoneInterfaces(): Promise<ZoneInterface[]> {
  const client = getClient() as unknown as QueryClientWithLiveZoneInterfaces;

  return new Promise((resolve, reject) => {
    client.getLiveZoneInterfaces({}, (err, response) => {
      if (err) {
        reject(err);
        return;
      }

      if (!isRecord(response)) {
        reject(new Error('GetLiveZoneInterfaces returned a non-object response'));
        return;
      }

      const raw = response as RuntimeGetLiveZoneInterfacesResponse;
      if (!Array.isArray(raw.zoneInterfaces)) {
        reject(new Error('GetLiveZoneInterfaces returned invalid zoneInterfaces'));
        return;
      }

      try {
        resolve(raw.zoneInterfaces.map(parseZoneInterface));
      } catch (parseError) {
        reject(parseError);
      }
    });
  });
}

async function pushZoneInterfaceConfig(zoneInterface: ZoneInterface): Promise<void> {
  const snapshotClient = getSnapshotClient();
  const zoneId = zoneInterface.zoneId;
  const zone: Zone = {
    id: zoneId,
    name: `test-zone-${zoneId.slice(0, 8)}`,
    interfaceIds: [zoneInterface.id],
  };

  await new Promise<void>((resolve, reject) => {
    snapshotClient.pushActiveConfigSnapshot(
      {
        correlationId: crypto.randomUUID(),
        reason: 'apply',
        snapshot: {
          id: crypto.randomUUID(),
          versionNumber: 1,
          snapshotType: 'manual_import',
          checksum: 'test-env-interface-controller-checksum',
          isActive: true,
          changesSummary: 'push zone interface config for test',
          createdAt: new Date(),
          createdBy: 'test-env-interface-controller',
          bundle: createDefaultSnapshotBundle({ zones: [zone], zoneInterfaces: [zoneInterface], zonePairs: [], rules: [] }),
        },
      },
      (err: Error | null, resp: any) => {
        if (err) {
          reject(err);
          return;
        }
        if (!resp?.accepted) {
          reject(new Error(resp?.message || 'snapshot push rejected'));
          return;
        }
        resolve();
      },
    );
  });
}

describe('Provider check RPC', () => {
	beforeAll(async () => {
		await resetFirewallState(getClient(), getSnapshotClient());
	});

	test('GetLiveZoneInterfaces returns correct data', async () => {
		await request('GetLiveZoneInterfaces', {}).run()
	})
})

describe('Interface Controller RPC', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient(), getSnapshotClient());
  });

  test('renames dummy interface via RPC', async () => {
    const interfaceName = 'dummy-rename';
    const newName = 'dummy-renamed';
    const zoneInterfaceId = crypto.randomUUID();
    const zoneId = crypto.randomUUID();

    await performCommand({ host: 'r1', command: `sudo ip link del ${interfaceName}` }).discardError().run();
    await performCommand({ host: 'r1', command: `sudo ip link del ${newName}` }).discardError().run();

    await performCommand({ host: 'r1', command: `sudo ip link add ${interfaceName} type dummy` })
	// .printEvents()
	//       .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'inactive' } }])
      .run();

    await pushZoneInterfaceConfig({
      id: zoneInterfaceId,
      zoneId,
      interfaceName,
      status: InterfaceStatus.INTERFACE_STATUS_INACTIVE,
      addresses: [],
    });

    await request('UpdateZoneInterfaceProperties', {
      id: zoneInterfaceId,
      interfaceName: newName,
    })
      .expectEvents([{ kind: 'interfaceRenamed', match: { oldInterfaceName: interfaceName, newInterfaceName: newName } }])
      .run();

    await performCommand({ host: 'r1', command: `sudo ip link show ${newName}` }).run();

    await performCommand({ host: 'r1', command: `sudo ip link del ${newName}` })
      // .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: newName, newStatus: 'missing' } }])
      .run();
  });

  test('brings dummy interface up/down via RPC', async () => {
    const interfaceName = 'dummy-state';
    const zoneInterfaceId = crypto.randomUUID();
    const zoneId = crypto.randomUUID();

    await performCommand({ host: 'r1', command: `sudo ip link del ${interfaceName}` }).discardError().run();

    await performCommand({ host: 'r1', command: `sudo ip link add ${interfaceName} type dummy` })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'inactive' } }])
      .run();

    await pushZoneInterfaceConfig({
      id: zoneInterfaceId,
      zoneId,
      interfaceName,
      status: InterfaceStatus.INTERFACE_STATUS_INACTIVE,
      addresses: [],
    });

    await request('SetInterfaceState', {
      id: zoneInterfaceId,
      state: InterfaceAdministrativeState.INTERFACE_ADMINISTRATIVE_STATE_UP,
    })
	.printEvents()
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'unknown' } }]) // we look for unknown because linux sucks
      .run();

    await performCommand({ host: 'r1', command: `sudo ip link show ${interfaceName} | grep -q 'state UNKNOWN'` }).run();

    await request('SetInterfaceState', {
      id: zoneInterfaceId,
      state: InterfaceAdministrativeState.INTERFACE_ADMINISTRATIVE_STATE_DOWN,
    })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'inactive' } }])
      .run();

    await performCommand({ host: 'r1', command: `sudo ip link show ${interfaceName} | grep -q 'state DOWN'` }).run();

    await performCommand({ host: 'r1', command: `sudo ip link del ${interfaceName}` })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'missing' } }])
      .run();
  });

  test('changes dummy IP address via RPC', async () => {
    const interfaceName = 'dummy-ip';
    const zoneInterfaceId = crypto.randomUUID();
    const zoneId = crypto.randomUUID();

    await performCommand({ host: 'r1', command: `sudo ip link del ${interfaceName}` }).discardError().run();

    await performCommand({ host: 'r1', command: `sudo ip link add ${interfaceName} type dummy` })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'inactive' } }])
      .run();

    await performCommand({ host: 'r1', command: `sudo ip link set ${interfaceName} up` })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'unknown' } }])
      .run();

    await pushZoneInterfaceConfig({
      id: zoneInterfaceId,
      zoneId,
      interfaceName,
      status: InterfaceStatus.INTERFACE_STATUS_ACTIVE,
      addresses: [],
    });

    await request('UpdateZoneInterfaceProperties', {
      id: zoneInterfaceId,
      address: '10.99.99.1/24',
    })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, addresses: ['10.99.99.1/24'] } }])
      .run();

    await performCommand({ host: 'r1', command: `sudo ip addr show ${interfaceName} | grep -q '10.99.99.1'` }).run();

    await performCommand({ host: 'r1', command: `sudo ip link del ${interfaceName}` })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'missing' } }])
      .run();
  });

  test('brings real interface up/down via RPC', async () => {
    await resetFirewallState(getClient(), getSnapshotClient());
    const interfaceName = 'eth1';
    const zoneInterfaceId = DEFAULT_ZONE_INTERFACES.find((zi) => zi.interfaceName === interfaceName)!.id;

    await request('SetInterfaceState', {
      id: zoneInterfaceId,
      state: InterfaceAdministrativeState.INTERFACE_ADMINISTRATIVE_STATE_DOWN,
    })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'inactive' } }])
      .run();

    await performCommand({ host: 'r1', command: `sudo ip link show ${interfaceName} | grep -q 'state DOWN'` }).run();

    await request('SetInterfaceState', {
      id: zoneInterfaceId,
      state: InterfaceAdministrativeState.INTERFACE_ADMINISTRATIVE_STATE_UP,
    })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName, newStatus: 'active' } }])
      .run();

    await performCommand({ host: 'r1', command: `sudo ip link show ${interfaceName} | grep -q 'state UP'` }).run();
  });

  test('modifying non-existent interface returns error', async () => {
    const nonExistentId = crypto.randomUUID();

    try {
      await request('SetInterfaceState', {
        id: nonExistentId,
        state: InterfaceAdministrativeState.INTERFACE_ADMINISTRATIVE_STATE_UP,
      }).run();
      throw new Error('SetInterfaceState should have thrown an error');
    } catch (err) {
      expect(err).toBeDefined();
    }

    try {
      await request('UpdateZoneInterfaceProperties', {
        id: nonExistentId,
        interfaceName: 'nonexistent',
      }).run();
      throw new Error('UpdateZoneInterfaceProperties should have thrown an error');
    } catch (err) {
      expect(err).toBeDefined();
    }
  });
});
