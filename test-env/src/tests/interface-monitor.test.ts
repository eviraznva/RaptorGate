import { beforeAll, describe, test } from 'bun:test';
import '../harness';
import {
  getClient,
  getSnapshotClient,
  resetFirewallState,
  performCommand,
} from '../harness';
import {
  InterfaceStatus,
  interfaceStatusFromJSON,
  type ZoneInterface,
} from '../generated/config/config_models';

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

function findZoneInterfaceByName(
  zoneInterfaces: ZoneInterface[],
  interfaceName: string,
): ZoneInterface {
  const zoneInterface = zoneInterfaces.find((item) => item.interfaceName === interfaceName);
  if (!zoneInterface) {
    throw new Error(`Missing expected interface in live response: ${interfaceName}`);
  }
  return zoneInterface;
}

describe('Interface Monitor', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient(), getSnapshotClient());
  });

  test('configured interfaces exist', async () => {
    const liveZoneInterfaces = await getLiveZoneInterfaces();

    for (const interfaceName of ['eth1', 'eth2']) {
      const live = findZoneInterfaceByName(liveZoneInterfaces, interfaceName);
      if (live.status === InterfaceStatus.INTERFACE_STATUS_MISSING) {
        throw new Error(`Interface ${interfaceName} unexpectedly reported as missing`);
      }
    }
  });

  test('detects interface status change', async () => {
    await performCommand({ host: 'r1', command: 'sudo ip link set eth1 down' })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: 'eth1', newStatus: 'inactive' } }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link set eth1 up' })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: 'eth1', newStatus: 'active' } }])
      .run();
  });

  test('detects interface rename', async () => {
    // Renaming requires the interface to be down
    await performCommand({ host: 'r1', command: 'sudo ip link set eth2 down' })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: 'eth2', newStatus: 'inactive' } }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link set eth2 name eth-test' })
      .expectEvents([{ kind: 'interfaceRenamed', match: { oldInterfaceName: 'eth2', newInterfaceName: 'eth-test' } }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link set eth-test name eth2' })
      .expectEvents([{ kind: 'interfaceRenamed', match: { oldInterfaceName: 'eth-test', newInterfaceName: 'eth2' } }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link set eth2 up' })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: 'eth2', newStatus: 'active' } }])
      .run();
  });

  test('detects dummy interface lifecycle', async () => {
    await performCommand({ host: 'r1', command: 'sudo ip link add dummy0 type dummy' })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: 'dummy0', newStatus: 'inactive' } }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link del dummy0' })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: 'dummy0', newStatus: 'missing' } }])
      .run();
  });

  test('detects address changes on dummy interface', async () => {
    await performCommand({ host: 'r1', command: 'sudo ip link add dummy1 type dummy' })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: 'dummy1' } }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip addr add 10.99.99.1/24 dev dummy1' })
      .expectEvents([{
        kind: 'interfaceStateChanged',
        match: {
          interfaceName: 'dummy1',
          addresses: ['10.99.99.1/24'],
        },
      }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link del dummy1' })
      .expectEvents([{ kind: 'interfaceStateChanged', match: { interfaceName: 'dummy1', newStatus: 'missing' } }])
      .run();
  });
});
