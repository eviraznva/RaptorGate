import { describe, test, beforeAll } from 'bun:test';
import '../harness';
import { performCommand, resetFirewallState, getClient } from '../harness';

describe('Command Output', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient());
  });

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

  test('h1 and h2 both can run commands', async () => {
    await performCommand({
      host: 'h1',
      command: 'hostname',
    })
      .expectOutput([/^h1$/])
      .run();

    await performCommand({
      host: 'h2',
      command: 'hostname',
    })
      .expectOutput([/^h2$/])
      .run();
  });

  test('ncat server on h2 responds to h1', async () => {
	await performCommand({
		host: 'h2',
		command: 'pkill -f ncat; pgrep -f nc'
	}).run()

    const server = await performCommand({
      host: 'h2',
      command: 'ncat -l -p 12345 -c "echo hello"',
    }).runDetached();

    server.defer_cleanup();

    await performCommand({
      host: 'h1',
      command: 'echo $(ncat 192.168.20.10 12345 --recv-only)', // wtf
    })
      .expectOutput([/hello/])
      .run();
  });
});
