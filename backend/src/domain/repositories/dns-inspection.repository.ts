import { DnsInspectionConfig } from "../entities/dns-inspection-config.entity.js";

export interface IDnsInspectionRepository {
  get(): Promise<DnsInspectionConfig>;
  save(config: DnsInspectionConfig): Promise<void>;
}

export const DNS_INSPECTION_REPOSITORY_TOKEN = Symbol(
  "DNS_INSPECTION_REPOSITORY_TOKEN",
);
