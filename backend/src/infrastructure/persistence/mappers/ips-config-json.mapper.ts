import { IpsConfig } from "src/domain/entities/ips-config.entity";
import { IpsConfigRecord } from "../schemas/ips-config.schema";
import { IpsSignatureJsonMapper } from "./ips-signature-json.mapper";

export class IpsConfigJsonMapper {
  constructor() {}

  static toRecord(ipsConfig: IpsConfig): IpsConfigRecord {
    return {
      general: ipsConfig.getGeneral(),
      detection: ipsConfig.getDetection(),
      signatures: ipsConfig
        .getSignatures()
        .map((signature) => IpsSignatureJsonMapper.toRecord(signature)),
    };
  }

  static toDomain(record: IpsConfigRecord): IpsConfig {
    return IpsConfig.create(
      record.general,
      record.detection,
      record.signatures.map((signature) =>
        IpsSignatureJsonMapper.toDomain(signature),
      ),
    );
  }
}
