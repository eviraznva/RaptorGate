import { describe, test, beforeAll } from 'bun:test';
import '../harness';
import { performCommand, resetFirewallState, getClient } from '../harness';

describe('Event Observation', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient());
  });

  // test('ping from h1 to h2 produces observable events', async () => {
  //   await performCommand({
  //     host: 'h1',
  //     command: 'ping -c 2 192.168.20.10',
  //   })
  //     .expectEvents([
  //       {
  //         kind: { item: 'tcpSessionEstablished' },
  //         match: {},
  //       },
  //     ])
  //     .run();
  // });

  test('command output on h1 matches expected ping pattern', async () => {
    await performCommand({
      host: 'h1',
      command: 'ping -c 2 192.168.20.10',
    })
      .expectOutput([
        /^PING 192\.168\.20\.10/,
        /bytes from 192\.168\.20\.10/,
      ])
      .run();
  });
});
