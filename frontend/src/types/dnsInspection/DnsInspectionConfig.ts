export type DnsTabKey = "general" | "blocklist" | "dnsTunneling" | "dnssec";

export type DnssecTransport = "udp" | "tcp" | "udpWithTcpFallback";
export type DnssecFailureAction = "allow" | "alert" | "block";

export interface DnsInspectionGeneralConfig {
  enabled: boolean;
}

export interface DnsInspectionBlocklistConfig {
  enabled: boolean;
  domains: string[];
}

export interface DnsInspectionDnsTunnelingConfig {
  enabled: boolean;
  maxLabelLength: number;
  entropyThreshold: number;
  windowSeconds: number;
  maxQueriesPerDomain: number;
  maxUniqueSubdomains: number;
  ignoreDomains: string[];
  alertThreshold: number;
  blockThreshold: number;
}

export interface DnsInspectionDnssecResolverEndpoint {
  address: string;
  port: number;
}

export interface DnsInspectionDnssecResolverConfig {
  primary: DnsInspectionDnssecResolverEndpoint;
  secondary: DnsInspectionDnssecResolverEndpoint;
  transport: DnssecTransport;
  timeoutMs: number;
  retries: number;
}

export interface DnsInspectionDnssecCacheTtlConfig {
  secure: number;
  insecure: number;
  bogus: number;
  failure: number;
}

export interface DnsInspectionDnssecCacheConfig {
  enabled: boolean;
  maxEntries: number;
  ttlSeconds: DnsInspectionDnssecCacheTtlConfig;
}

export interface DnsInspectionDnssecConfig {
  enabled: boolean;
  maxLookupsPerPacket: number;
  defaultOnResolverFailure: DnssecFailureAction;
  resolver: DnsInspectionDnssecResolverConfig;
  cache: DnsInspectionDnssecCacheConfig;
}

export interface DnsInspectionConfig {
  general: DnsInspectionGeneralConfig;
  blocklist: DnsInspectionBlocklistConfig;
  dnsTunneling: DnsInspectionDnsTunnelingConfig;
  dnssec: DnsInspectionDnssecConfig;
}

export interface DnsInspectionState {
  activeTab: DnsTabKey;
  draftConfig: DnsInspectionConfig;
  appliedConfig: DnsInspectionConfig;
}

export const dnsTabs: Array<{ key: DnsTabKey; label: string }> = [
  { key: "general", label: "General" },
  { key: "blocklist", label: "Blocklist" },
  { key: "dnsTunneling", label: "DNS Tunneling" },
  { key: "dnssec", label: "DNSSEC" },
];

export const defaultDnsInspectionConfig: DnsInspectionConfig = {
  general: { enabled: false },
  blocklist: { enabled: false, domains: [] },
  dnsTunneling: {
    enabled: false,
    maxLabelLength: 40,
    entropyThreshold: 3.5,
    windowSeconds: 60,
    maxQueriesPerDomain: 100,
    maxUniqueSubdomains: 20,
    ignoreDomains: [],
    alertThreshold: 0.6,
    blockThreshold: 0.85,
  },
  dnssec: {
    enabled: false,
    maxLookupsPerPacket: 1,
    defaultOnResolverFailure: "allow",
    resolver: {
      primary: { address: "127.0.0.1", port: 53 },
      secondary: { address: "", port: 53 },
      transport: "udpWithTcpFallback",
      timeoutMs: 2000,
      retries: 1,
    },
    cache: {
      enabled: true,
      maxEntries: 4096,
      ttlSeconds: {
        secure: 300,
        insecure: 300,
        bogus: 60,
        failure: 15,
      },
    },
  },
};
