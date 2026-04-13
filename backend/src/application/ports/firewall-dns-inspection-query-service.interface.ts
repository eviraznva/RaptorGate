import type { DnsInspectionConfig } from "../../domain/entities/dns-inspection-config.entity.js";

export interface IFirewallDnsInspectionQueryService {
  swapDnsInspectionConfig(config: DnsInspectionConfig): Promise<void>;
  getDnsInspectionConfig(): Promise<DnsInspectionConfig>;
}

export const FIREWALL_DNS_INSPECTION_QUERY_SERVICE_TOKEN = Symbol(
  "FIREWALL_DNS_INSPECTION_QUERY_SERVICE_TOKEN",
);
