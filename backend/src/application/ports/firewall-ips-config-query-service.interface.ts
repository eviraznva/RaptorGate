import { IpsConfig } from "src/domain/entities/ips-config.entity";

export interface IFirewallIpsConfigQueryService {
  swapIpsConfig(config: IpsConfig): Promise<void>;
  getIpsConfig(): Promise<IpsConfig>;
}

export const FIREWALL_IPS_CONFIG_QUERY_SERVICE_TOKEN = Symbol(
  "FIREWALL_IPS_CONFIG_QUERY_SERVICE_TOKEN",
);
