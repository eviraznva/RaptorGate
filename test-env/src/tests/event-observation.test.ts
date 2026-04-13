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

  test('nc from h1 to h2 produces events for full tcp session', async () => {
	  await performCommand({
		  host: 'h2',
		  command: 'sudo pkill -f ncat; sudo pgrep -f nc'
	  })
	  .discardError()
	  .run()

	  const server = await performCommand({
		  host: 'h2',
		  command: 'ncat -l -p 12345 -c "echo hello"',
	  }).runDetached();

	  server.defer_cleanup()

    await performCommand({
      host: 'h1',
      command: 'echo $(ncat 192.168.20.10 12345 --recv-only)',
    })
      .expectEvents([
		  {
			  kind: 'tcpSessionEstablished',
			  match: {}
		  }
	  ])
      .run();
  }, { timeout: 10_000 })
});
