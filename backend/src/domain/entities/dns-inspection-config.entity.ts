import { IpAddress } from "../value-objects/ip-address.vo.js";
import { Port } from "../value-objects/port.vo.js";

export type DnssecTransport = "udp" | "tcp" | "udpWithTcpFallback";
export type DnssecFailureAction = "allow" | "alert" | "block";

export interface DnsInspectionGeneralSection {
  enabled: boolean;
}

export interface DnsInspectionBlocklistSection {
  enabled: boolean;
  domains: string[];
}

export interface DnsInspectionDnsTunnelingSection {
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
  address: IpAddress | null;
  port: Port;
}

export interface DnsInspectionDnssecResolverSection {
  primary: DnsInspectionDnssecResolverEndpoint;
  secondary: DnsInspectionDnssecResolverEndpoint;
  transport: DnssecTransport;
  timeoutMs: number;
  retries: number;
}

export interface DnsInspectionDnssecCacheTtlSection {
  secure: number;
  insecure: number;
  bogus: number;
  failure: number;
}

export interface DnsInspectionDnssecCacheSection {
  enabled: boolean;
  maxEntries: number;
  ttlSeconds: DnsInspectionDnssecCacheTtlSection;
}

export interface DnsInspectionDnssecSection {
  enabled: boolean;
  maxLookupsPerPacket: number;
  defaultOnResolverFailure: DnssecFailureAction;
  resolver: DnsInspectionDnssecResolverSection;
  cache: DnsInspectionDnssecCacheSection;
}

export class DnsInspectionConfig {
  private constructor(
    private readonly general: DnsInspectionGeneralSection,
    private readonly blocklist: DnsInspectionBlocklistSection,
    private readonly dnsTunneling: DnsInspectionDnsTunnelingSection,
    private readonly dnssec: DnsInspectionDnssecSection,
  ) {}

  public static create(
    general: DnsInspectionGeneralSection,
    blocklist: DnsInspectionBlocklistSection,
    dnsTunneling: DnsInspectionDnsTunnelingSection,
    dnssec: DnsInspectionDnssecSection,
  ): DnsInspectionConfig {
    return new DnsInspectionConfig(general, blocklist, dnsTunneling, dnssec);
  }

  public getGeneral(): DnsInspectionGeneralSection {
    return this.general;
  }

  public getBlocklist(): DnsInspectionBlocklistSection {
    return this.blocklist;
  }

  public getDnsTunneling(): DnsInspectionDnsTunnelingSection {
    return this.dnsTunneling;
  }

  public getDnssec(): DnsInspectionDnssecSection {
    return this.dnssec;
  }
}
