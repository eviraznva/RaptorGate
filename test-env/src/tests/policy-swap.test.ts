import { describe, test, beforeAll } from 'bun:test';
import '../harness';
import {
  request,
  resetFirewallState,
  getClient,
  getSnapshotClient,
} from '../harness';
import { P } from 'ts-pattern';
import {
  createDefaultSnapshotBundle,
  DEFAULT_POLICIES,
} from '../harness/fixtures';

function buildSnapshotBundle(ruleContent: string, ruleName: string, zonePairId?: string) {
  const defaultRule = DEFAULT_POLICIES[0]!;
  return createDefaultSnapshotBundle({
    rules: [{
      ...defaultRule,
      id: crypto.randomUUID(),
      name: ruleName,
      content: ruleContent,
      zonePairId: zonePairId ?? defaultRule.zonePairId,
    }],
  });
}

describe('Policy Swap', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient(), getSnapshotClient());
  });

  test('snapshot with invalid RaptorLang returns error', async () => {
    try {
      await request('PushActiveConfigSnapshot', {
        correlationId: crypto.randomUUID(),
        reason: 'apply',
        snapshot: {
          id: crypto.randomUUID(),
          versionNumber: 1,
          snapshotType: 'manual_import',
          checksum: 'policy-swap-invalid-checksum',
          isActive: true,
          changesSummary: 'invalid policy snapshot',
          createdAt: new Date(),
          createdBy: 'policy-swap-test',
          bundle: buildSnapshotBundle(
            'this is not valid raptorlang',
            'invalid-rule',
          ),
        },
      }).run();
      throw new Error('Expected PushActiveConfigSnapshot to fail');
    } catch (err: any) {
      if (err.message === 'Expected PushActiveConfigSnapshot to fail') throw err;
    }
  });

  test('get policies returns swapped rule', async () => {
    const ruleName = `test-policy-${Date.now()}`;

    await request('PushActiveConfigSnapshot', {
      correlationId: crypto.randomUUID(),
      reason: 'apply',
      snapshot: {
        id: crypto.randomUUID(),
        versionNumber: 1,
        snapshotType: 'manual_import',
        checksum: 'policy-swap-get-checksum',
        isActive: true,
        changesSummary: 'fetch policies snapshot',
        createdAt: new Date(),
        createdBy: 'policy-swap-test',
        bundle: buildSnapshotBundle(
          'match ip_ver { =v4: verdict allow }',
          ruleName,
        ),
      },
    }).run();

    await request('GetPolicies', {})
      .expectResponse(
        P.when((res: any) =>
          res && Array.isArray(res.rules) && res.rules.some((r: any) => r.name === ruleName),
        ),
      )
      .run();
  });
});
