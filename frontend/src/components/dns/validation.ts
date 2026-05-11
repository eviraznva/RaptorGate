import type { DnsInspectionConfig } from "../../types/dnsInspection/DnsInspectionConfig";

export function validateDnsInspectionConfig(config: DnsInspectionConfig): string[] {
  const errors: string[] = [];

  if (!config.dnssec.resolver.primary.address.trim()) {
    errors.push("DNSSEC: primary resolver address is required.");
  }

  if (
    config.dnssec.resolver.primary.port < 1 ||
    config.dnssec.resolver.primary.port > 65535
  ) {
    errors.push("DNSSEC: primary resolver port must be 1..65535.");
  }

  if (config.dnssec.resolver.secondary.address.trim()) {
    if (
      config.dnssec.resolver.secondary.port < 1 ||
      config.dnssec.resolver.secondary.port > 65535
    ) {
      errors.push("DNSSEC: secondary resolver port must be 1..65535.");
    }
  }

  if (config.dnsTunneling.alertThreshold < 0 || config.dnsTunneling.alertThreshold > 1) {
    errors.push("DNS Tunneling: alert threshold must be in range 0..1.");
  }

  if (config.dnsTunneling.blockThreshold < 0 || config.dnsTunneling.blockThreshold > 1) {
    errors.push("DNS Tunneling: block threshold must be in range 0..1.");
  }

  if (config.dnsTunneling.alertThreshold > config.dnsTunneling.blockThreshold) {
    errors.push("DNS Tunneling: alert threshold must be <= block threshold.");
  }

  return errors;
}
