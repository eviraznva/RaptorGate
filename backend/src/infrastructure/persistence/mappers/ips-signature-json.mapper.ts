import { IpsSignature } from "src/domain/entities/ips-signature.entity";
import { IpsAction } from "src/domain/value-objects/ips-action.vo";
import { IpsAppProtocol } from "src/domain/value-objects/ips-app-protocol.vo";
import { Port } from "src/domain/value-objects/port.vo";
import { RegexPattern } from "src/domain/value-objects/regex-pattern.vo";
import { SignatureCategory } from "src/domain/value-objects/signature-category.vo";
import { SignatureSeverity } from "src/domain/value-objects/signature-severity.vo";
import { IpsSignatureRecord } from "../schemas/ips-signatures.schema";

export class IpsSignatureJsonMapper {
  constructor() {}

  static toRecord(signature: IpsSignature): IpsSignatureRecord {
    return {
      id: signature.getId(),
      name: signature.getName(),
      isActive: signature.getIsActive(),
      category: signature.getCategory().getValue(),
      pattern: signature.getPattern().getValue(),
      severity: signature.getSeverity().getValue(),
      action: signature.getAction().getValue(),
      appProtocols: signature
        .getAppProtocols()
        .map((appProtocol) => appProtocol.getValue()),
      srcPorts: signature.getSrcPorts().map((port) => port.getValue),
      dstPorts: signature.getDstPorts().map((port) => port.getValue),
      createdAt: signature.getCreatedAt().toISOString(),
      updatedAt: signature.getUpdatedAt().toISOString(),
    };
  }

  static toDomain(record: IpsSignatureRecord): IpsSignature {
    return IpsSignature.create(
      record.id,
      record.name,
      record.isActive,
      SignatureCategory.create(record.category),
      RegexPattern.create(record.pattern),
      SignatureSeverity.create(record.severity),
      IpsAction.create(record.action),
      record.appProtocols.map((appProtocol) =>
        IpsAppProtocol.create(appProtocol),
      ),
      record.srcPorts.map((port) => Port.create(port)),
      record.dstPorts.map((port) => Port.create(port)),
      new Date(record.createdAt),
      new Date(record.updatedAt),
    );
  }
}
