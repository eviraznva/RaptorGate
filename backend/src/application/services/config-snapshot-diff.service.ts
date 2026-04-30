import { Injectable } from '@nestjs/common';
import type { ConfigSnapshotPayload } from '../../domain/value-objects/config-snapshot-payload.interface.js';
import type {
  ConfigDiffChange,
  ConfigDiffChangeType,
  ConfigDiffResult,
  ConfigDiffSection,
  ConfigDiffSummary,
} from '../dtos/get-config-diff.dto.js';

type PlainValue =
  | null
  | string
  | number
  | boolean
  | PlainValue[]
  | { [key: string]: PlainValue };

type DiffValue = PlainValue | undefined;

const REDACTED_VALUE = '[redacted]';

const SENSITIVE_KEYS = new Set([
  'passwordHash',
  'refreshToken',
  'recoveryToken',
  'certificatePem',
  'privateKeyRef',
]);

const COLLECTION_SECTIONS: {
  section: ConfigDiffSection;
  path: readonly string[];
}[] = [
  { section: 'rules', path: ['bundle', 'rules', 'items'] },
  { section: 'zones', path: ['bundle', 'zones', 'items'] },
  { section: 'zone_interfaces', path: ['bundle', 'zone_interfaces', 'items'] },
  { section: 'zone_pairs', path: ['bundle', 'zone_pairs', 'items'] },
  { section: 'nat_rules', path: ['bundle', 'nat_rules', 'items'] },
  { section: 'dns_blacklist', path: ['bundle', 'dns_blacklist', 'items'] },
  { section: 'ssl_bypass_list', path: ['bundle', 'ssl_bypass_list', 'items'] },
  { section: 'ips_signatures', path: ['bundle', 'ips_signatures', 'items'] },
  {
    section: 'firewall_certificates',
    path: ['bundle', 'firewall_certificates', 'items'],
  },
  { section: 'users', path: ['bundle', 'users', 'items'] },
];

const OBJECT_SECTIONS: {
  section: ConfigDiffSection;
  path: readonly string[];
}[] = [
  {
    section: 'tls_inspection_policy',
    path: ['bundle', 'tls_inspection_policy'],
  },
  { section: 'ml_model', path: ['bundle', 'ml_model'] },
];

@Injectable()
export class ConfigSnapshotDiffService {
  diff(
    basePayload: ConfigSnapshotPayload,
    targetPayload: ConfigSnapshotPayload,
  ): ConfigDiffResult {
    const base = this.toPlain(basePayload);
    const target = this.toPlain(targetPayload);
    const changes: ConfigDiffChange[] = [];

    for (const { section, path } of COLLECTION_SECTIONS) {
      changes.push(
        ...this.diffCollection(
          this.readPath(base, path),
          this.readPath(target, path),
          section,
          path.join('.'),
        ),
      );
    }

    for (const { section, path } of OBJECT_SECTIONS) {
      changes.push(
        ...this.diffValue(
          this.readPath(base, path),
          this.readPath(target, path),
          section,
          path.join('.'),
        ),
      );
    }

    return {
      summary: this.buildSummary(changes),
      changes,
    };
  }

  private diffCollection(
    before: DiffValue,
    after: DiffValue,
    section: ConfigDiffSection,
    path: string,
  ): ConfigDiffChange[] {
    const beforeItems = Array.isArray(before)
      ? before.filter((item) => this.isRecord(item))
      : [];
    const afterItems = Array.isArray(after)
      ? after.filter((item) => this.isRecord(item))
      : [];

    const beforeById = this.indexById(beforeItems);
    const afterById = this.indexById(afterItems);
    const ids = [...new Set([...beforeById.keys(), ...afterById.keys()])].sort();

    return ids.flatMap((id) => {
      const beforeItem = beforeById.get(id);
      const afterItem = afterById.get(id);
      const itemPath = `${path}.${id}`;

      if (!beforeItem && afterItem) {
        return [
          this.createChange('added', section, itemPath, undefined, afterItem, id),
        ];
      }

      if (beforeItem && !afterItem) {
        return [
          this.createChange(
            'removed',
            section,
            itemPath,
            beforeItem,
            undefined,
            id,
          ),
        ];
      }

      return this.diffValue(beforeItem, afterItem, section, itemPath, id);
    });
  }

  private diffValue(
    before: DiffValue,
    after: DiffValue,
    section: ConfigDiffSection,
    path: string,
    entityId?: string,
  ): ConfigDiffChange[] {
    if (before === undefined && after === undefined) return [];

    if (before === undefined) {
      return [
        this.createChange('added', section, path, undefined, after, entityId),
      ];
    }

    if (after === undefined) {
      return [
        this.createChange('removed', section, path, before, undefined, entityId),
      ];
    }

    const normalizedBefore = this.normalizeValue(before);
    const normalizedAfter = this.normalizeValue(after);

    if (this.areEqual(normalizedBefore, normalizedAfter)) return [];

    if (this.isRecord(normalizedBefore) && this.isRecord(normalizedAfter)) {
      const keys = [
        ...new Set([
          ...Object.keys(normalizedBefore),
          ...Object.keys(normalizedAfter),
        ]),
      ].sort();

      return keys.flatMap((key) => {
        const childPath = `${path}.${key}`;
        const hasBefore = Object.prototype.hasOwnProperty.call(
          normalizedBefore,
          key,
        );
        const hasAfter = Object.prototype.hasOwnProperty.call(
          normalizedAfter,
          key,
        );

        if (!hasBefore) {
          return [
            this.createChange(
              'added',
              section,
              childPath,
              undefined,
              normalizedAfter[key],
              entityId,
            ),
          ];
        }

        if (!hasAfter) {
          return [
            this.createChange(
              'removed',
              section,
              childPath,
              normalizedBefore[key],
              undefined,
              entityId,
            ),
          ];
        }

        return this.diffValue(
          normalizedBefore[key],
          normalizedAfter[key],
          section,
          childPath,
          entityId,
        );
      });
    }

    return [
      this.createChange(
        'modified',
        section,
        path,
        normalizedBefore,
        normalizedAfter,
        entityId,
      ),
    ];
  }

  private createChange(
    type: ConfigDiffChangeType,
    section: ConfigDiffSection,
    path: string,
    before?: DiffValue,
    after?: DiffValue,
    entityId?: string,
  ): ConfigDiffChange {
    const change: ConfigDiffChange = {
      type,
      section,
      path,
      entityId,
    };

    if (type !== 'added') {
      change.before = this.redactValue(path, before);
    }

    if (type !== 'removed') {
      change.after = this.redactValue(path, after);
    }

    return change;
  }

  private buildSummary(changes: ConfigDiffChange[]): ConfigDiffSummary {
    const summary: ConfigDiffSummary = {
      added: 0,
      removed: 0,
      modified: 0,
      bySection: {},
    };

    for (const change of changes) {
      summary[change.type] += 1;

      const sectionSummary = summary.bySection[change.section] ?? {
        added: 0,
        removed: 0,
        modified: 0,
      };

      sectionSummary[change.type] += 1;
      summary.bySection[change.section] = sectionSummary;
    }

    return summary;
  }

  private indexById(items: Record<string, PlainValue>[]) {
    const indexed = new Map<string, Record<string, PlainValue>>();

    items.forEach((item, index) => {
      const id =
        typeof item.id === 'string' || typeof item.id === 'number'
          ? String(item.id)
          : `index:${index}`;

      indexed.set(id, item);
    });

    return indexed;
  }

  private readPath(root: DiffValue, path: readonly string[]): DiffValue {
    let current = root;

    for (const segment of path) {
      if (!this.isRecord(current)) return undefined;
      current = current[segment];
    }

    return current;
  }

  private toPlain(value: unknown): DiffValue {
    if (value === undefined || typeof value === 'function') return undefined;
    if (value === null) return null;
    if (value instanceof Date) return value.toISOString();

    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    ) {
      return value;
    }

    if (typeof value === 'bigint') {
      return value.toString();
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.toPlain(item) ?? null);
    }

    if (typeof value === 'object') {
      const entries = Object.entries(value as Record<string, unknown>).filter(
        ([, entryValue]) => typeof entryValue !== 'function',
      );

      if (entries.length === 1 && entries[0][0] === 'value') {
        return this.toPlain(entries[0][1]);
      }

      const result: Record<string, PlainValue> = {};

      for (const [key, entryValue] of entries.sort(([a], [b]) =>
        a.localeCompare(b),
      )) {
        const plain = this.toPlain(entryValue);
        if (plain !== undefined) result[key] = plain;
      }

      return result;
    }

    return String(value);
  }

  private normalizeValue(value: DiffValue): DiffValue {
    if (value === undefined) return undefined;

    if (Array.isArray(value)) {
      const normalized = value.map((item) => this.normalizeValue(item) ?? null);

      if (normalized.every((item) => this.isScalar(item))) {
        return [...normalized].sort((a, b) =>
          String(a).localeCompare(String(b)),
        );
      }

      return normalized;
    }

    if (this.isRecord(value)) {
      const result: Record<string, PlainValue> = {};

      for (const key of Object.keys(value).sort()) {
        const normalized = this.normalizeValue(value[key]);
        if (normalized !== undefined) result[key] = normalized;
      }

      return result;
    }

    return value;
  }

  private redactValue(path: string, value: DiffValue): unknown {
    if (value === undefined) return undefined;

    const fieldName = path.split('.').pop();
    if (fieldName && SENSITIVE_KEYS.has(fieldName)) {
      return REDACTED_VALUE;
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.redactValue(path, item) ?? null);
    }

    if (this.isRecord(value)) {
      const result: Record<string, unknown> = {};

      for (const [key, childValue] of Object.entries(value)) {
        const redacted = this.redactValue(`${path}.${key}`, childValue);
        if (redacted !== undefined) result[key] = redacted;
      }

      return result;
    }

    return value;
  }

  private areEqual(before: DiffValue, after: DiffValue): boolean {
    return JSON.stringify(before) === JSON.stringify(after);
  }

  private isRecord(value: unknown): value is Record<string, PlainValue> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  private isScalar(value: unknown): boolean {
    return (
      value === null ||
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    );
  }
}
