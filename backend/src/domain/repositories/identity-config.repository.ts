import { IdentityConfiguration } from '../entities/identity-configuration.entity.js';

export interface IIdentityConfigRepository {
  exists(): Promise<boolean>;
  find(): Promise<IdentityConfiguration>;
  save(config: IdentityConfiguration): Promise<void>;
  overwrite(config: IdentityConfiguration): Promise<void>;
  mutate(
    transform: (
      config: IdentityConfiguration,
    ) => IdentityConfiguration | Promise<IdentityConfiguration>,
  ): Promise<IdentityConfiguration>;
}

export const IDENTITY_CONFIG_REPOSITORY_TOKEN = Symbol('IDENTITY_CONFIG_REPOSITORY_TOKEN');
