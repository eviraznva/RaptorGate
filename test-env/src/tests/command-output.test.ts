import { describe, test, beforeAll } from 'bun:test';
import '../harness';
import { performCommand, resetFirewallState, getClient } from '../harness';

describe('Command Output', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient());
  });

  test('ip route show on h1 shows default gateway', async () => {
    await performCommand({
      host: 'h1',
      command: 'ip route show',
    })
      .expectOutput([/default via 192\.168\.10\.254/])
      .run({ timeout: 5_000 });
  });

  test('hostname on h1 returns h1', async () => {
    await performCommand({
      host: 'h1',
      command: 'hostname',
    })
      .expectOutput([/^h1$/])
      .run({ timeout: 5_000 });
  });

  test('ncat server on h2 responds to h1', async () => {
    await performCommand({
      host: 'h2',
      command: 'ncat -l -k -p 8080 -c "echo hello"',
    }).run();

    await performCommand({
      host: 'h1',
      command: 'echo test | ncat 192.168.20.10 8080',
    })
      .expectOutput([/hello/])
      .run({ timeout: 10_000 });
  });
});
