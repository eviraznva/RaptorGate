import { IpsAction } from "../value-objects/ips-action.vo.js";
import { IpsAppProtocol } from "../value-objects/ips-app-protocol.vo.js";
import { Port } from "../value-objects/port.vo.js";
import { RegexPattern } from "../value-objects/regex-pattern.vo.js";
import { SignatureCategory } from "../value-objects/signature-category.vo.js";
import { SignatureSeverity } from "../value-objects/signature-severity.vo.js";

export class IpsSignature {
  private constructor(
    private readonly id: string,
    private name: string,
    private isActive: boolean,
    private category: SignatureCategory,
    private pattern: RegexPattern,
    private severity: SignatureSeverity,
    private action: IpsAction,
    private appProtocols: IpsAppProtocol[],
    private srcPorts: Port[],
    private dstPorts: Port[],
    private readonly createdAt: Date,
    private updatedAt: Date,
  ) {}

  public static create(
    id: string,
    name: string,
    isActive: boolean,
    category: SignatureCategory,
    pattern: RegexPattern,
    severity: SignatureSeverity,
    action: IpsAction,
    appProtocols: IpsAppProtocol[],
    srcPorts: Port[],
    dstPorts: Port[],
    createdAt: Date,
    updatedAt: Date,
  ): IpsSignature {
    return new IpsSignature(
      id,
      name,
      isActive,
      category,
      pattern,
      severity,
      action,
      appProtocols,
      srcPorts,
      dstPorts,
      createdAt,
      updatedAt,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getName(): string {
    return this.name;
  }

  public getCategory(): SignatureCategory {
    return this.category;
  }

  public getPattern(): RegexPattern {
    return this.pattern;
  }

  public getSeverity(): SignatureSeverity {
    return this.severity;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getAction(): IpsAction {
    return this.action;
  }

  public getAppProtocols(): IpsAppProtocol[] {
    return this.appProtocols;
  }

  public getSrcPorts(): Port[] {
    return this.srcPorts;
  }

  public getDstPorts(): Port[] {
    return this.dstPorts;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }
}
