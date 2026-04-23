import { beforeAll, describe, test } from 'bun:test';
import '../harness';
import {
  getClient,
  getSnapshotClient,
  request,
  resetFirewallState,
} from '../harness';
import { createDefaultSnapshotBundle, DEFAULT_ZONES } from '../harness/fixtures';
import {
  InterfaceStatus,
  interfaceStatusFromJSON,
  type ZoneInterface,
} from '../generated/config/config_models';

type PushSnapshotResponse = {
  accepted?: boolean;
  message?: string;
};

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

  test('loopback and others exist', async () => {
    const configuredZoneInterfaces: ZoneInterface[] = DEFAULT_ZONES.flatMap((zone) =>
      zone.interfaceIds.map((interfaceName) => ({
        id: crypto.randomUUID(),
        zoneId: zone.id,
        interfaceName,
        status: InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED,
        addresses: [],
      })),
    );

    configuredZoneInterfaces.push({
      id: crypto.randomUUID(),
      zoneId: DEFAULT_ZONES[0]!.id,
      interfaceName: 'lo',
      status: InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED,
      addresses: [],
    });

    await request('PushActiveConfigSnapshot', {
      correlationId: crypto.randomUUID(),
      reason: 'apply',
      snapshot: {
        id: crypto.randomUUID(),
        versionNumber: 1,
        snapshotType: 'manual_import',
        checksum: 'interface-monitor-loopback-checksum',
        isActive: true,
        changesSummary: 'interface monitor loopback baseline',
        createdAt: new Date(),
        createdBy: 'interface-monitor-test',
        bundle: createDefaultSnapshotBundle({
          zoneInterfaces: configuredZoneInterfaces,
        }),
      },
    })
      .expectResponse((response: PushSnapshotResponse) => response.accepted === true)
      .run();

    const liveZoneInterfaces = await getLiveZoneInterfaces();

    for (const configured of configuredZoneInterfaces) {
      const live = findZoneInterfaceByName(liveZoneInterfaces, configured.interfaceName);
      if (live.status === InterfaceStatus.INTERFACE_STATUS_MISSING) {
        throw new Error(`Interface ${configured.interfaceName} unexpectedly reported as missing`);
      }
    }

    const loopback = findZoneInterfaceByName(liveZoneInterfaces, 'lo');
    if (loopback.addresses.length === 0) {
      throw new Error('Loopback interface should have at least one address in live response');
    }
  });
});
