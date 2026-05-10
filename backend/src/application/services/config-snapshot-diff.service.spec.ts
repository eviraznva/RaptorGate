import type { ConfigSnapshotPayload } from '../../domain/value-objects/config-snapshot-payload.interface.js';
import { ConfigSnapshotDiffService } from './config-snapshot-diff.service.js';

const payload = (
  bundle: Record<string, unknown>,
): ConfigSnapshotPayload =>
  ({
    bundle: {
      rules: { items: [] },
      zones: { items: [] },
      zone_interfaces: { items: [] },
      zone_pairs: { items: [] },
      nat_rules: { items: [] },
      dns_blacklist: { items: [] },
      ssl_bypass_list: { items: [] },
      ips_signatures: { items: [] },
      ml_model: null,
      firewall_certificates: { items: [] },
      users: { items: [] },
      ...bundle,
    },
  }) as ConfigSnapshotPayload;

describe('ConfigSnapshotDiffService', () => {
  let service: ConfigSnapshotDiffService;

  beforeEach(() => {
    service = new ConfigSnapshotDiffService();
  });

  it('returns empty diff when payloads are equal', () => {
    const source = payload({
      rules: { items: [{ id: 'rule-1', action: 'allow' }] },
    });

    expect(service.diff(source, source)).toEqual({
      summary: {
        added: 0,
        removed: 0,
        modified: 0,
        bySection: {},
      },
      changes: [],
    });
  });

  it('maps added values to changes and summary', () => {
    const result = service.diff(
      payload({ rules: { items: [] } }),
      payload({ rules: { items: [{ id: 'rule-1', action: 'allow' }] } }),
    );

    expect(result).toEqual({
      summary: {
        added: 2,
        removed: 0,
        modified: 0,
        bySection: {
          rules: {
            added: 2,
            removed: 0,
            modified: 0,
          },
        },
      },
      changes: [
        {
          type: 'added',
          section: 'rules',
          path: 'rules.items.0.action',
          entityId: 'rule-1',
          before: undefined,
          after: 'allow',
        },
        {
          type: 'added',
          section: 'rules',
          path: 'rules.items.0.id',
          entityId: 'rule-1',
          before: undefined,
          after: 'rule-1',
        },
      ],
    });
  });

  it('maps removed values to changes and summary', () => {
    const result = service.diff(
      payload({ zones: { items: [{ id: 'zone-1', name: 'lan' }] } }),
      payload({ zones: { items: [] } }),
    );

    expect(result).toEqual({
      summary: {
        added: 0,
        removed: 2,
        modified: 0,
        bySection: {
          zones: {
            added: 0,
            removed: 2,
            modified: 0,
          },
        },
      },
      changes: [
        {
          type: 'removed',
          section: 'zones',
          path: 'zones.items.0.id',
          entityId: 'zone-1',
          before: 'zone-1',
          after: undefined,
        },
        {
          type: 'removed',
          section: 'zones',
          path: 'zones.items.0.name',
          entityId: 'zone-1',
          before: 'lan',
          after: undefined,
        },
      ],
    });
  });

  it('maps updated values to changes with before and after values', () => {
    const result = service.diff(
      payload({ nat_rules: { items: [{ id: 'nat-1', enabled: true }] } }),
      payload({ nat_rules: { items: [{ id: 'nat-1', enabled: false }] } }),
    );

    expect(result).toEqual({
      summary: {
        added: 0,
        removed: 0,
        modified: 1,
        bySection: {
          nat_rules: {
            added: 0,
            removed: 0,
            modified: 1,
          },
        },
      },
      changes: [
        {
          type: 'modified',
          section: 'nat_rules',
          path: 'nat_rules.items.0.enabled',
          entityId: 'nat-1',
          before: true,
          after: false,
        },
      ],
    });
  });

  it('handles nested non-item sections without entityId', () => {
    const result = service.diff(
      payload({ tls_inspection_policy: { block_all_ech: false } }),
      payload({ tls_inspection_policy: { block_all_ech: true } }),
    );

    expect(result.changes).toEqual([
      {
        type: 'modified',
        section: 'tls_inspection_policy',
        path: 'tls_inspection_policy.block_all_ech',
        entityId: undefined,
        before: false,
        after: true,
      },
    ]);
  });

  it('redacts sensitive values', () => {
    const result = service.diff(
      payload({ users: { items: [{ id: 'user-1', passwordHash: 'old-hash' }] } }),
      payload({ users: { items: [{ id: 'user-1', passwordHash: 'new-hash' }] } }),
    );

    expect(result.changes).toEqual([
      {
        type: 'modified',
        section: 'users',
        path: 'users.items.0.passwordHash',
        entityId: 'user-1',
        before: '[redacted]',
        after: '[redacted]',
      },
    ]);
  });

  it('returns deterministic ordering by section path and type', () => {
    const result = service.diff(
      payload({
        rules: { items: [{ id: 'rule-1', priority: 10 }] },
        zones: { items: [{ id: 'zone-1', name: 'lan' }] },
      }),
      payload({
        rules: { items: [{ id: 'rule-1', priority: 20 }] },
        zones: { items: [{ id: 'zone-1', name: 'wan' }] },
      }),
    );

    expect(result.changes.map((change) => change.path)).toEqual([
      'rules.items.0.priority',
      'zones.items.0.name',
    ]);
  });
});
