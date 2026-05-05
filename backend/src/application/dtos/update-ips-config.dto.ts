import {
  IpsDetectionConfig,
  IpsGeneralConfig,
} from "src/domain/entities/ips-config.entity";

export interface Signature {
  name: string;
  enabled: boolean;
  category: string;
  pattern: string;
  matchType?: string;
  patternEncoding?: string;
  caseInsensitive?: boolean;
  severity: string;
  action: string;
  appProtocols: string[];
  srcPorts: number[];
  dstPorts: number[];
}

export class IpsConfigDto {
  general: IpsGeneralConfig;
  detection: IpsDetectionConfig;
  signatures: Signature[];
}
