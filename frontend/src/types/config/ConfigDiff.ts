export type ConfigDiffChangeType = 'added' | 'removed' | 'modified';

export type ConfigDiffSnapshotMeta = {
  id: string;
  versionNumber: number;
  checksum: string;
  createdAt: string;
};

export type ConfigDiffSummaryBySection = {
  added: number;
  removed: number;
  modified: number;
};

export type ConfigDiffSummary = {
  added: number;
  removed: number;
  modified: number;
  bySection: Record<string, ConfigDiffSummaryBySection>;
};

export type ConfigDiffChange = {
  type: ConfigDiffChangeType;
  section: string;
  path: string;
  entityId?: string;
  before?: unknown;
  after?: unknown;
};

export type ConfigDiffResult = {
  baseSnapshot: ConfigDiffSnapshotMeta;
  targetSnapshot: ConfigDiffSnapshotMeta;
  summary: ConfigDiffSummary;
  changes: ConfigDiffChange[];
};
