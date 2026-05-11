export class IpsAppProtocolIsInvalidException extends Error {
  constructor(protocol: string) {
    super(
      `The IPS app protocol "${protocol}" is invalid. Allowed values are: IPS_APP_PROTOCOL_UNSPECIFIED, IPS_APP_PROTOCOL_HTTP, IPS_APP_PROTOCOL_TLS, IPS_APP_PROTOCOL_DNS, IPS_APP_PROTOCOL_SSH, IPS_APP_PROTOCOL_FTP, IPS_APP_PROTOCOL_SMTP, IPS_APP_PROTOCOL_RDP, IPS_APP_PROTOCOL_SMB, IPS_APP_PROTOCOL_QUIC, IPS_APP_PROTOCOL_UNKNOWN, UNRECOGNIZED.`,
    );

    this.name = "IpsAppProtocolIsInvalidException";
  }
}
