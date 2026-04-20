import { IpsAppProtocolIsInvalidException } from "../exceptions/ips-app-protocol-is-invalid.exception.js";

export type IpsAppProtocolType =
  | "IPS_APP_PROTOCOL_UNSPECIFIED"
  | "IPS_APP_PROTOCOL_HTTP"
  | "IPS_APP_PROTOCOL_TLS"
  | "IPS_APP_PROTOCOL_DNS"
  | "IPS_APP_PROTOCOL_SSH"
  | "IPS_APP_PROTOCOL_FTP"
  | "IPS_APP_PROTOCOL_SMTP"
  | "IPS_APP_PROTOCOL_RDP"
  | "IPS_APP_PROTOCOL_SMB"
  | "IPS_APP_PROTOCOL_QUIC"
  | "IPS_APP_PROTOCOL_UNKNOWN"
  | "UNRECOGNIZED";

export class IpsAppProtocol {
  private static readonly ALLOWED_VALUES: IpsAppProtocolType[] = [
    "IPS_APP_PROTOCOL_UNSPECIFIED",
    "IPS_APP_PROTOCOL_HTTP",
    "IPS_APP_PROTOCOL_TLS",
    "IPS_APP_PROTOCOL_DNS",
    "IPS_APP_PROTOCOL_SSH",
    "IPS_APP_PROTOCOL_FTP",
    "IPS_APP_PROTOCOL_SMTP",
    "IPS_APP_PROTOCOL_RDP",
    "IPS_APP_PROTOCOL_SMB",
    "IPS_APP_PROTOCOL_QUIC",
    "IPS_APP_PROTOCOL_UNKNOWN",
    "UNRECOGNIZED",
  ];

  private readonly value: IpsAppProtocolType;

  private constructor(protocol: IpsAppProtocolType) {
    this.value = protocol;
  }

  public static create(protocol: string): IpsAppProtocol {
    if (!IpsAppProtocol.isValidType(protocol)) {
      throw new IpsAppProtocolIsInvalidException(protocol);
    }
    return new IpsAppProtocol(protocol as IpsAppProtocolType);
  }

  private static isValidType(type: string): boolean {
    return IpsAppProtocol.ALLOWED_VALUES.includes(type as IpsAppProtocolType);
  }

  public getValue(): IpsAppProtocolType {
    return this.value;
  }
}
