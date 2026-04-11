import { describe, test, beforeAll } from 'bun:test';
import '../harness';
import { request, resetFirewallState, getClient } from '../harness';
import { P } from 'ts-pattern';

describe('Policy Swap', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient());
  });

  test('swap policies with valid RaptorLang returns success', async () => {
    await request({
      rpc: 'SwapPolicies',
      body: {
        rules: [
          {
            id: crypto.randomUUID(),
            name: 'allow-icmp-v4',
            zone_pair_id: crypto.randomUUID(),
            priority: 0,
            content:
              'match ip_ver { =v4: match protocol { =icmp: verdict allow } =v6: verdict drop }',
          },
        ],
      },
    }).run();
  });

  test('swap policies with invalid RaptorLang returns error', async () => {
    try {
      await request({
        rpc: 'SwapPolicies',
        body: {
          rules: [
            {
              id: crypto.randomUUID(),
              name: 'invalid-rule',
              zone_pair_id: crypto.randomUUID(),
              priority: 0,
              content: 'this is not valid raptorlang',
            },
          ],
        },
      }).run();
      throw new Error('Expected SwapPolicies to fail');
    } catch (err: any) {
      if (err.message === 'Expected SwapPolicies to fail') throw err;
    }
  });

  test('get policies returns swapped rule', async () => {
    const ruleName = `test-policy-${Date.now()}`;

    await request({
      rpc: 'SwapPolicies',
      body: {
        rules: [
          {
            id: crypto.randomUUID(),
            name: ruleName,
            zone_pair_id: crypto.randomUUID(),
            priority: 0,
            content: 'match ip_ver { =v4: verdict allow }',
          },
        ],
      },
    }).run();

    await request({ rpc: 'GetPolicies', body: {} })
      .expectResponse(
        P.when((rules: unknown) =>
          Array.isArray(rules) && rules.some((r: any) => r.name === ruleName),
        ),
      )
      .run();
  });
});
