export type IpsTabKey = "general" | "detection" | "signatures";

export type IpsSeverity = "info" | "low" | "medium" | "high" | "critical";
export type IpsAction = "alert" | "block";
export type IpsMatchType = "literal" | "regex";
export type IpsPatternEncoding = "text" | "hex";
export type IpsAppProtocol =
  | "http"
  | "tls"
  | "dns"
  | "ssh"
  | "ftp"
  | "smtp"
  | "rdp"
  | "smb"
  | "quic"
  | "unknown";

export interface IpsGeneralConfig {
  enabled: boolean;
}

export interface IpsDetectionConfig {
  enabled: boolean;
  maxPayloadBytes: number;
  maxMatchesPerPacket: number;
}

export interface IpsSignatureConfig {
  id: string;
  name: string;
  enabled: boolean;
  category: string;
  pattern: string;
  matchType: IpsMatchType;
  patternEncoding: IpsPatternEncoding;
  caseInsensitive: boolean;
  severity: IpsSeverity;
  action: IpsAction;
  appProtocols: IpsAppProtocol[];
  srcPorts: number[];
  dstPorts: number[];
}

export interface IpsConfig {
  general: IpsGeneralConfig;
  detection: IpsDetectionConfig;
  signatures: IpsSignatureConfig[];
}

export interface IpsConfigState {
  activeTab: IpsTabKey;
  draftConfig: IpsConfig;
  appliedConfig: IpsConfig;
  selectedSignatureId: string | null;
}

export const ipsTabs: Array<{ key: IpsTabKey; label: string }> = [
  { key: "general", label: "General" },
  { key: "detection", label: "Detection" },
  { key: "signatures", label: "Signatures" },
];

export const ipsSeverityOptions: IpsSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

export const ipsActionOptions: IpsAction[] = ["alert", "block"];
export const ipsMatchTypeOptions: IpsMatchType[] = ["literal", "regex"];
export const ipsPatternEncodingOptions: IpsPatternEncoding[] = ["text", "hex"];

export const ipsAppProtocolOptions: IpsAppProtocol[] = [
  "http",
  "tls",
  "dns",
  "ssh",
  "ftp",
  "smtp",
  "rdp",
  "smb",
  "quic",
  "unknown",
];

export const defaultIpsConfig: IpsConfig = {
  general: { enabled: false },
  detection: {
    enabled: false,
    maxPayloadBytes: 4096,
    maxMatchesPerPacket: 8,
  },
  signatures: [],
};
