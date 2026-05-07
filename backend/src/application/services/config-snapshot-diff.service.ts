import { Injectable } from '@nestjs/common';
import { detailedDiff } from 'deep-object-diff';
import type { ConfigSnapshotPayload } from '../../domain/value-objects/config-snapshot-payload.interface.js';
import type {
  ConfigDiffChange,
  ConfigDiffChangeType,
  ConfigDiffResult,
  ConfigDiffSection,
  ConfigDiffSectionSummary,
  ConfigDiffSummary,
} from '../dtos/get-config-diff.dto.js';

// Local shape of deep-object-diff detailedDiff output.
type DeepDiffResult = {
  // Values present only in target snapshot.
  added?: unknown;
  // Values present only in base snapshot.
  deleted?: unknown;
  // Values present in both snapshots but with different value.
  updated?: unknown;
};

// Sections allowed in public diff response.
const CONFIG_DIFF_SECTIONS = new Set<ConfigDiffSection>([
  'rules',
  'zones',
  'zone_interfaces',
  'zone_pairs',
  'nat_rules',
  'dns_blacklist',
  'ssl_bypass_list',
  'ips_signatures',
  'firewall_certificates',
  'users',
  'tls_inspection_policy',
  'ml_model',
]);

// Public replacement for values that must not leave backend.
const REDACTED_VALUE = '[redacted]';

// Field names whose before/after values are hidden in diff output.
const SENSITIVE_KEYS = new Set([
  'passwordHash',
  'refreshToken',
  'recoveryToken',
  'certificatePem',
  'privateKeyRef',
]);

@Injectable()
export class ConfigSnapshotDiffService {
  // Public entrypoint used by GetConfigDiffUseCase.
  diff(
    basePayload: ConfigSnapshotPayload,
    targetPayload: ConfigSnapshotPayload,
  ): ConfigDiffResult {
    // Compare bundles directly so paths start with section names.
    const detailedChanges = detailedDiff(
      basePayload.bundle,
      targetPayload.bundle,
    ) as DeepDiffResult;

    // Normalize library branches into one API-level change list.
    const changes = [
      // deep-object-diff added branch maps to API added changes.
      ...this.toChanges(
        'added',
        detailedChanges.added,
        basePayload.bundle,
        targetPayload.bundle,
      ),
      // deep-object-diff deleted branch maps to API removed changes.
      ...this.toChanges(
        'removed',
        detailedChanges.deleted,
        basePayload.bundle,
        targetPayload.bundle,
      ),
      // deep-object-diff updated branch maps to API modified changes.
      ...this.toChanges(
        'modified',
        detailedChanges.updated,
        basePayload.bundle,
        targetPayload.bundle,
      ),
    ].sort((left, right) =>
      // Stable ordering makes tests and API responses deterministic.
      `${left.section}.${left.path}.${left.type}`.localeCompare(
        `${right.section}.${right.path}.${right.type}`,
      ),
    );

    return {
      // Summary is derived from final changes, not from raw diff tree.
      summary: this.toSummary(changes),
      changes,
    };
  }

  // Recursively flattens one detailedDiff branch into API changes.
  private toChanges(
    type: ConfigDiffChangeType,
    diffNode: unknown,
    baseBundle: ConfigSnapshotPayload['bundle'],
    targetBundle: ConfigSnapshotPayload['bundle'],
    path: string[] = [],
  ): ConfigDiffChange[] {
    // Missing root branch means this change type has no changes.
    if (path.length === 0 && diffNode === undefined) {
      return [];
    }

    // Deleted arrays/objects may appear as undefined in library output.
    if (type === 'removed' && diffNode === undefined) {
      // Read original value from base so deleted fields can be expanded.
      const baseValue = this.getValue(baseBundle, path);

      // If deleted value has children, emit one change per deleted leaf.
      if (this.isBranch(baseValue)) {
        return Object.entries(baseValue).flatMap(([key, value]) =>
          this.toChanges(type, value, baseBundle, targetBundle, [...path, key]),
        );
      }
    }

    // Non-branch value is a leaf and becomes one ConfigDiffChange.
    if (!this.isBranch(diffNode)) {
      // Section is first path segment under bundle.
      const section = this.toSection(path);

      // Ignore unknown roots to keep response inside known config sections.
      if (!section) {
        return [];
      }

      return [
        {
          type,
          section,
          // Convert path segments into public dot path.
          path: path.join('.'),
          // Entity id exists mainly for section.items[index] paths.
          entityId: this.toEntityId(path, baseBundle, targetBundle),
          // Added values have no base-side value.
          before:
            type === 'added'
              ? undefined
              : this.redactValue(path, this.getValue(baseBundle, path)),
          // Removed values have no target-side value.
          after:
            type === 'removed'
              ? undefined
              : this.redactValue(path, this.getValue(targetBundle, path)),
        },
      ];
    }

    // Branch value is traversed until leaf changes are found.
    return Object.entries(diffNode).flatMap(([key, value]) =>
      this.toChanges(type, value, baseBundle, targetBundle, [...path, key]),
    );
  }

  // Builds global and per-section counters from final change list.
  private toSummary(changes: ConfigDiffChange[]): ConfigDiffSummary {
    // Initial counters start empty for every change type.
    const summary: ConfigDiffSummary = {
      added: 0,
      removed: 0,
      modified: 0,
      bySection: {},
    };

    for (const change of changes) {
      // Increment global counter matching change type.
      summary[change.type] += 1;

      // Reuse existing section counter or create fresh one.
      const sectionSummary =
        summary.bySection[change.section] ?? this.emptySectionSummary();

      // Increment same type counter inside section bucket.
      sectionSummary[change.type] += 1;
      summary.bySection[change.section] = sectionSummary;
    }

    return summary;
  }

  // Creates independent empty counter for one section.
  private emptySectionSummary(): ConfigDiffSectionSummary {
    return {
      added: 0,
      removed: 0,
      modified: 0,
    };
  }

  // Converts first path segment into typed config section.
  private toSection(path: string[]): ConfigDiffSection | undefined {
    const [section] = path;

    // Runtime check protects DTO from paths outside known sections.
    if (CONFIG_DIFF_SECTIONS.has(section as ConfigDiffSection)) {
      return section as ConfigDiffSection;
    }

    return undefined;
  }

  // Extracts entity id from paths shaped like section.items.index.field.
  private toEntityId(
    path: string[],
    baseBundle: ConfigSnapshotPayload['bundle'],
    targetBundle: ConfigSnapshotPayload['bundle'],
  ): string | undefined {
    // Items marker identifies collection-style config sections.
    const itemsIndex = path.indexOf('items');

    // Non-collection sections do not have entity ids.
    if (itemsIndex === -1) {
      return undefined;
    }

    // Keep section.items.index, drop changed field suffix.
    const entityPath = path.slice(0, itemsIndex + 2);
    // Prefer target for added/modified entities, fallback to base for removed.
    const entity =
      this.getValue(targetBundle, entityPath) ??
      this.getValue(baseBundle, entityPath);

    // Only object entities can expose id property.
    if (!this.isPlainObject(entity)) {
      return undefined;
    }

    // DTO expects string entity ids.
    return typeof entity.id === 'string' ? entity.id : undefined;
  }

  // Replaces sensitive field values with a safe placeholder.
  private redactValue(path: string[], value: unknown): unknown {
    // Last path segment is changed field name.
    const fieldName = path.at(-1);

    // Hide value when field name is listed as sensitive.
    if (fieldName && SENSITIVE_KEYS.has(fieldName)) {
      return REDACTED_VALUE;
    }

    return value;
  }

  // Reads nested value from object/array by path segments.
  private getValue(source: unknown, path: string[]): unknown {
    return path.reduce<unknown>((current, segment) => {
      // Stop safely when path reaches missing or null branch.
      if (current === null || current === undefined) {
        return undefined;
      }

      // Array segments come from Object.entries as numeric strings.
      if (Array.isArray(current)) {
        return current[Number(segment)];
      }

      // Object segments are normal property names.
      if (this.isPlainObject(current)) {
        return current[segment];
      }

      // Primitive value cannot be traversed deeper.
      return undefined;
    }, source);
  }

  // Branch means value can have nested diff children.
  private isBranch(value: unknown): value is Record<string, unknown> | unknown[] {
    return typeof value === 'object' && value !== null;
  }

  // Plain object excludes arrays so property access stays predictable.
  private isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}
