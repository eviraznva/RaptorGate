import { IpsSignature } from "./ips-signature.entity";

export interface IpsDetectionConfig {
  enabled: boolean;
  maxPayloadBytes: number;
  maxMatchesPerPacket: number;
}

export interface IpsGeneralConfig {
  enabled: boolean;
}

export class IpsConfig {
  private constructor(
    private general: IpsGeneralConfig,
    private detection: IpsDetectionConfig,
    private signatures: IpsSignature[],
  ) {}

  static create(
    general: IpsGeneralConfig,
    detection: IpsDetectionConfig,
    signatures: IpsSignature[],
  ): IpsConfig {
    return new IpsConfig(general, detection, signatures);
  }

  public getGeneral(): IpsGeneralConfig {
    return this.general;
  }

  public getDetection(): IpsDetectionConfig {
    return this.detection;
  }

  public getSignatures(): IpsSignature[] {
    return this.signatures;
  }
}
