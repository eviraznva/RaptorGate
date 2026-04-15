import { IpsConfig } from "src/domain/entities/ips-config.entity";
import {
  IpsAction,
  IpsActionType,
} from "src/domain/value-objects/ips-action.vo";
import {
  IpsAppProtocol,
  IpsAppProtocolType,
} from "src/domain/value-objects/ips-app-protocol.vo";
import {
  SignatureSeverity,
  SignatureSeverityType,
} from "src/domain/value-objects/signature-severity.vo";
import { IpsConfigResponseDto } from "../dtos/ips-config-response.dto";
import * as IpsDto from "../dtos/update-ips-config.dto";

export function mapSeverityToDto(vo: SignatureSeverity): IpsDto.IpsSeverity {
  switch (vo.getValue()) {
    case "SEVERITY_INFO":
      return "info";
    case "SEVERITY_LOW":
      return "low";
    case "SEVERITY_MEDIUM":
      return "medium";
    case "SEVERITY_HIGH":
      return "high";
    case "SEVERITY_CRITICAL":
      return "critical";
    case "SEVERITY_UNSPECIFIED":
      return "unspecified";
    default:
      return "unrecognized";
  }
}

export function mapActionToDto(vo: IpsAction): IpsDto.IpsAction {
  switch (vo.getValue()) {
    case "IPS_ACTION_ALERT":
      return "alert";
    case "IPS_ACTION_BLOCK":
      return "block";
    case "IPS_ACTION_UNSPECIFIED":
      return "unspecified";
    default:
      return "unrecognized";
  }
}

export function mapProtocolToDto(vo: IpsAppProtocol): IpsDto.IpsAppProtocol {
  switch (vo.getValue()) {
    case "IPS_APP_PROTOCOL_HTTP":
      return "http";
    case "IPS_APP_PROTOCOL_TLS":
      return "tls";
    case "IPS_APP_PROTOCOL_DNS":
      return "dns";
    case "IPS_APP_PROTOCOL_SSH":
      return "ssh";
    case "IPS_APP_PROTOCOL_FTP":
      return "ftp";
    case "IPS_APP_PROTOCOL_SMTP":
      return "smtp";
    case "IPS_APP_PROTOCOL_RDP":
      return "rdp";
    case "IPS_APP_PROTOCOL_SMB":
      return "smb";
    case "IPS_APP_PROTOCOL_QUIC":
      return "quic";
    case "IPS_APP_PROTOCOL_UNKNOWN":
      return "unknown";
    default:
      return "unknown";
  }
}

export function mapSeverityFromDtoValue(
  dto: IpsDto.IpsSeverity,
): SignatureSeverityType {
  switch (dto) {
    case "info":
      return "SEVERITY_INFO";
    case "low":
      return "SEVERITY_LOW";
    case "medium":
      return "SEVERITY_MEDIUM";
    case "high":
      return "SEVERITY_HIGH";
    case "critical":
      return "SEVERITY_CRITICAL";
    case "unspecified":
      return "SEVERITY_UNSPECIFIED";
    default:
      return "UNRECOGNIZED";
  }
}

export function mapActionFromDtoValue(dto: IpsDto.IpsAction): IpsActionType {
  switch (dto) {
    case "alert":
      return "IPS_ACTION_ALERT";
    case "block":
      return "IPS_ACTION_BLOCK";
    case "unspecified":
      return "IPS_ACTION_UNSPECIFIED";
    default:
      return "UNRECOGNIZED";
  }
}

export function mapProtocolFromDtoValue(
  dto: IpsDto.IpsAppProtocol,
): IpsAppProtocolType {
  switch (dto) {
    case "http":
      return "IPS_APP_PROTOCOL_HTTP";
    case "tls":
      return "IPS_APP_PROTOCOL_TLS";
    case "dns":
      return "IPS_APP_PROTOCOL_DNS";
    case "ssh":
      return "IPS_APP_PROTOCOL_SSH";
    case "ftp":
      return "IPS_APP_PROTOCOL_FTP";
    case "smtp":
      return "IPS_APP_PROTOCOL_SMTP";
    case "rdp":
      return "IPS_APP_PROTOCOL_RDP";
    case "smb":
      return "IPS_APP_PROTOCOL_SMB";
    case "quic":
      return "IPS_APP_PROTOCOL_QUIC";
    case "unknown":
    default:
      return "IPS_APP_PROTOCOL_UNKNOWN";
  }
}

export class IpsConfigResponseMapper {
  constructor() {}

  static toDto(ipsConfig: IpsConfig): IpsConfigResponseDto {
    return {
      general: ipsConfig.getGeneral(),
      detection: ipsConfig.getDetection(),
      signatures: ipsConfig.getSignatures().map((signature) => {
        return {
          id: signature.getId(),
          name: signature.getName(),
          enabled: signature.getIsActive(),
          category: signature.getCategory().getValue(),
          pattern: signature.getPattern().getValue(),
          severity: mapSeverityToDto(signature.getSeverity()),
          action: mapActionToDto(signature.getAction()),
          appProtocols: signature
            .getAppProtocols()
            .map((IpsAppProtocol) => mapProtocolToDto(IpsAppProtocol)),
          srcPorts: signature.getSrcPorts().map((port) => port.getValue),
          dstPorts: signature.getDstPorts().map((port) => port.getValue),
        };
      }),
    };
  }
}
