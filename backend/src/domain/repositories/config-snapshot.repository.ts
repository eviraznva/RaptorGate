import { ConfigurationSnapshot } from '../entities/configuration-snapshot.entity';

export interface IConfigSnapshotRepository {
  save(configSnapshot: ConfigurationSnapshot): Promise<void>;
  findActiveSnapshot(): Promise<ConfigurationSnapshot | null>;
  findAllSnapshots(): Promise<ConfigurationSnapshot[]>;
  findById(id: string): Promise<ConfigurationSnapshot | null>;
}

export const CONFIG_SNAPSHOT_REPOSITORY_TOKEN = Symbol(
  'CONFIG_SNAPSHOT_REPOSITORY_TOKEN',
);
