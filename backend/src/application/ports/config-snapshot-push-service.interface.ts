import type { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';

export type ConfigSnapshotPushReason =
  | 'apply'
  | 'rollback'
  | 'manual_sync'
  | 'import';

export interface IConfigSnapshotPushService {
  pushActiveConfigSnapshot(
    snapshot: ConfigurationSnapshot,
    reason: ConfigSnapshotPushReason,
  ): Promise<void>;
}

export const CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN = Symbol(
  'CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN',
);
