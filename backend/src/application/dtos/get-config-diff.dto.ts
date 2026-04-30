export type ConfigDiffChangeType = 'added' | 'removed' | 'modified';

export type ConfigDiffSection =
  | 'rules'
  | 'zones'
  | 'zone_interfaces'
  | 'zone_pairs'
  | 'nat_rules'
  | 'dns_blacklist'
  | 'ssl_bypass_list'
  | 'ips_signatures'
  | 'firewall_certificates'
  | 'users'
  | 'tls_inspection_policy'
  | 'ml_model';

export interface ConfigDiffSnapshotMeta {
  id: string;
  versionNumber: number;
  checksum: string;
  createdAt: string;
}

export interface ConfigDiffSectionSummary {
  added: number;
  removed: number;
  modified: number;
}

export interface ConfigDiffSummary extends ConfigDiffSectionSummary {
  bySection: Partial<Record<ConfigDiffSection, ConfigDiffSectionSummary>>;
}

export interface ConfigDiffChange {
  type: ConfigDiffChangeType;
  section: ConfigDiffSection;
  path: string;
  entityId?: string;
  before?: unknown;
  after?: unknown;
}

export interface ConfigDiffResult {
  summary: ConfigDiffSummary;
  changes: ConfigDiffChange[];
}

export class GetConfigDiffDto {
  baseSnapshot: ConfigDiffSnapshotMeta;
  targetSnapshot: ConfigDiffSnapshotMeta;
  summary: ConfigDiffSummary;
  changes: ConfigDiffChange[];
}
