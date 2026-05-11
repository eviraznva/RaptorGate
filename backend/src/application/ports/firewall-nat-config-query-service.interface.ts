import { NatRule } from "src/domain/entities/nat-rule.entity";

export interface IFirewallNatConfigQueryService {
  swapNatConfig(rules: NatRule[]): Promise<void>;
  getNatConfig(): Promise<NatRule[]>;
}

export const FIREWALL_NAT_CONFIG_QUERY_SERVICE_TOKEN = Symbol(
  "FIREWALL_NAT_CONFIG_QUERY_SERVICE_TOKEN",
);
