export type LoginResponse = {
  id: string;
  username: string;
  createdAt: string;
  accessToken: string;
};

export type {
  DnsInspectionConfig,
  DnsInspectionState,
  DnsTabKey,
  DnssecFailureAction,
  DnssecTransport,
} from "./dnsInspection/DnsInspectionConfig";

export type {
  IpsAction,
  IpsAppProtocol,
  IpsConfig,
  IpsConfigState,
  IpsSeverity,
  IpsTabKey,
} from "./ipsConfig/IpsConfig";
