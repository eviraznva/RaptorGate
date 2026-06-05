import type { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';

export type ConfigSnapshotPushReason =
  | 'apply'
  | 'rollback'
  | 'manual_sync'
  | 'import'
  | 'decryption_mirror_update'
  | 'ssl_bypass_update';

export interface FactoryResetCommand {
  reason?: string;
  clearPki?: boolean;
  clearServerKeys?: boolean;
}

export interface FactoryResetResult {
  correlationId: string;
  accepted: boolean;
  message: string;
  safeStateApplied: boolean;
  removedServerKeys: number;
  removedServerKeyFiles: number;
  removedCaFiles: number;
}

export interface IConfigSnapshotPushService {
  pushActiveConfigSnapshot(
    snapshot: ConfigurationSnapshot,
    reason: ConfigSnapshotPushReason,
  ): Promise<void>;

  factoryReset(command: FactoryResetCommand): Promise<FactoryResetResult>;
}

export const CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN = Symbol(
  'CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN',
);
