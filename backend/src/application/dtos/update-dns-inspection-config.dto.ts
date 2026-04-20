import type {
  DnsInspectionBlocklistSection,
  DnsInspectionDnsTunnelingSection,
  DnsInspectionGeneralSection,
  DnssecFailureAction,
  DnssecTransport,
} from "../../domain/entities/dns-inspection-config.entity.js";

export interface UpdateDnsInspectionDnssecResolverEndpointDto {
  address: string;
  port: number;
}

export interface UpdateDnsInspectionDnssecResolverDto {
  primary: UpdateDnsInspectionDnssecResolverEndpointDto;
  secondary: UpdateDnsInspectionDnssecResolverEndpointDto;
  transport: DnssecTransport;
  timeoutMs: number;
  retries: number;
}

export interface UpdateDnsInspectionDnssecCacheTtlDto {
  secure: number;
  insecure: number;
  bogus: number;
  failure: number;
}

export interface UpdateDnsInspectionDnssecCacheDto {
  enabled: boolean;
  maxEntries: number;
  ttlSeconds: UpdateDnsInspectionDnssecCacheTtlDto;
}

export interface UpdateDnsInspectionDnssecDto {
  enabled: boolean;
  maxLookupsPerPacket: number;
  defaultOnResolverFailure: DnssecFailureAction;
  resolver: UpdateDnsInspectionDnssecResolverDto;
  cache: UpdateDnsInspectionDnssecCacheDto;
}

export class UpdateDnsInspectionConfigDto {
  general: DnsInspectionGeneralSection;
  blocklist: DnsInspectionBlocklistSection;
  dnsTunneling: DnsInspectionDnsTunnelingSection;
  dnssec: UpdateDnsInspectionDnssecDto;
}
