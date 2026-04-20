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
import { randomUUIDv7 } from 'bun';

function buildSnapshotRequest(options: {
  ruleContent: string;
  ruleName: string;
  checksum: string;
  changesSummary: string;
  zonePairId?: string;
}) {
  const defaultRule = DEFAULT_POLICIES[0]!;
  return {
    correlationId: crypto.randomUUID(),
    reason: 'apply',
    snapshot: {
      id: crypto.randomUUID(),
      versionNumber: 1,
      snapshotType: 'manual_import',
      checksum: options.checksum,
      isActive: true,
      changesSummary: options.changesSummary,
      createdAt: new Date(),
      createdBy: 'snapshot-integrity-test',
      bundle: createDefaultSnapshotBundle({
        rules: [{
          ...defaultRule,
          id: crypto.randomUUID(),
          name: options.ruleName,
          content: options.ruleContent,
          zonePairId: options.zonePairId ?? defaultRule.zonePairId,
        }],
      }),
    },
  };
}

describe('Snapshot Integrity', () => {
  beforeAll(async () => {
    await resetFirewallState(getClient(), getSnapshotClient());
  });

  test('successful replacement swaps active policies', async () => {
    const initialRuleName = `initial-policy-${Date.now()}`;
    const replacementRuleName = `replacement-policy-${Date.now()}`;

    await request('PushActiveConfigSnapshot', buildSnapshotRequest({
      ruleContent: 'match ip_ver { =v4: verdict allow }',
      ruleName: initialRuleName,
      checksum: 'snapshot-integrity-initial-checksum',
      changesSummary: 'initial policy snapshot',
    }))
      .expectResponse(
        P.when((res: any) => res?.accepted === true),
      )
      .run();

    await request('PushActiveConfigSnapshot', buildSnapshotRequest({
      ruleContent: 'match ip_ver { =v6: verdict drop }',
      ruleName: replacementRuleName,
      checksum: 'snapshot-integrity-replacement-checksum',
      changesSummary: 'replacement policy snapshot',
    }))
      .expectResponse(
        P.when((res: any) => res?.accepted === true),
      )
      .run();

    await request('GetPolicies', {})
      .expectResponse(
        P.when((res: any) =>
          res &&
          Array.isArray(res.rules) &&
          res.rules.some((r: any) => r.name === replacementRuleName) &&
          !res.rules.some((r: any) => r.name === initialRuleName),
        ),
      )
      .run();
  });

  test('broken integrity returns rejected response payload', async () => {
    const missingZonePairId = crypto.randomUUID();

    await request('PushActiveConfigSnapshot', buildSnapshotRequest({
      ruleContent: 'match ip_ver { =v4: verdict allow }',
      ruleName: 'broken-integrity-policy',
      checksum: 'snapshot-integrity-broken-checksum',
      changesSummary: 'broken integrity policy snapshot',
      zonePairId: missingZonePairId,
    }))
      .expectResponse(
        P.when((res: any) => res?.accepted === false && typeof res?.message === 'string' && res.message.length > 0),
      )
      .run();
  });
});
