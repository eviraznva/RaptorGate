import { beforeAll, describe, test } from 'bun:test';
import '../harness';
import {
  getClient,
  getSnapshotClient,
  resetFirewallState,
  performCommand,
} from '../harness';
import { sleep } from 'bun';

describe('Route Events', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient(), getSnapshotClient());
  });

  test('emits RouteAdded when a new route is created', async () => {
    await performCommand({ host: 'r1', command: 'sudo ip route del 10.99.99.0/24 dev dummy-add' })
      .discardError()
      .run();
    await performCommand({ host: 'r1', command: 'sudo ip link del dummy-add' })
      .discardError()
      .run();
	await sleep(100);

    await performCommand({ host: 'r1', command: 'sudo ip link add dummy-add type dummy' }).run();
    await performCommand({ host: 'r1', command: 'sudo ip link set dummy-add up' }).run();
	await sleep(100);

    await performCommand({ host: 'r1', command: 'sudo ip route add 10.99.99.0/24 dev dummy-add' })
		.printEvents()
      .expectEvents([{
        kind: 'routeAdded',
        match: { route: { destination: '10.99.99.0/24' } }
      }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link del dummy-add' }).run();
  });

  test('emits RouteModified when an existing route is changed', async () => {
    await performCommand({ host: 'r1', command: 'sudo ip route del 10.88.88.0/24 dev dummy-mod' })
      .discardError()
      .run();
    await performCommand({ host: 'r1', command: 'sudo ip link del dummy-mod' })
      .discardError()
      .run();
	await sleep(100);

    await performCommand({ host: 'r1', command: 'sudo ip link add dummy-mod type dummy' }).run();
    await performCommand({ host: 'r1', command: 'sudo ip link set dummy-mod up' }).run();
	await sleep(100);

    await performCommand({ host: 'r1', command: 'sudo ip route add 10.88.88.0/24 dev dummy-mod metric 100' }).run();
	await sleep(100);

    await performCommand({ host: 'r1', command: 'sudo ip route replace 10.88.88.0/24 dev dummy-mod metric 200' })
      .expectEvents([{
        kind: 'routeModified',
        match: {
          oldRoute: { destination: '10.88.88.0/24', priority: 100 },
          newRoute: { destination: '10.88.88.0/24', priority: 200 }
        }
      }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link del dummy-mod' }).run();
  });

  test('emits RouteDeleted when a route is removed', async () => {
    await performCommand({ host: 'r1', command: 'sudo ip route del 10.77.77.0/24 dev dummy-del' })
      .discardError()
      .run();
    await performCommand({ host: 'r1', command: 'sudo ip link del dummy-del' })
      .discardError()
      .run();
	await sleep(100);

    await performCommand({ host: 'r1', command: 'sudo ip link add dummy-del type dummy' }).run();
    await performCommand({ host: 'r1', command: 'sudo ip link set dummy-del up' }).run();
	await sleep(100);

    await performCommand({ host: 'r1', command: 'sudo ip route add 10.77.77.0/24 dev dummy-del' }).run();
	await sleep(100);

    await performCommand({ host: 'r1', command: 'sudo ip route del 10.77.77.0/24 dev dummy-del' })
      .expectEvents([{
        kind: 'routeDeleted',
        match: { route: { destination: '10.77.77.0/24' } }
      }])
      .run();

    await performCommand({ host: 'r1', command: 'sudo ip link del dummy-del' }).run();
  });
});
