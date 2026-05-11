import { IpsConfig } from "../entities/ips-config.entity";

export type IIpsConfigRepository = {
  get(): Promise<IpsConfig>;
  save(ispConfig: IpsConfig): Promise<void>;
};

export const IPS_CONFIG_REPOSITORY_TOKEN = Symbol(
  "IPS_CONFIG_REPOSITORY_TOKEN",
);
