import { IpsSignatureConfigIsInvalidException } from "../exceptions/ips-signature-config-is-invalid.exception.js";
import { IpsAction } from "../value-objects/ips-action.vo.js";
import { IpsAppProtocol } from "../value-objects/ips-app-protocol.vo.js";
import { IpsMatchType } from "../value-objects/ips-match-type.vo.js";
import { IpsPatternEncoding } from "../value-objects/ips-pattern-encoding.vo.js";
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
    private matchType: IpsMatchType,
    private patternEncoding: IpsPatternEncoding,
    private caseInsensitive: boolean,
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
    matchType: IpsMatchType,
    patternEncoding: IpsPatternEncoding,
    caseInsensitive: boolean,
    severity: SignatureSeverity,
    action: IpsAction,
    appProtocols: IpsAppProtocol[],
    srcPorts: Port[],
    dstPorts: Port[],
    createdAt: Date,
    updatedAt: Date,
  ): IpsSignature {
    IpsSignature.assertRuntimeOptionsAreValid(
      id,
      pattern,
      matchType,
      patternEncoding,
      caseInsensitive,
    );

    return new IpsSignature(
      id,
      name,
      isActive,
      category,
      pattern,
      matchType,
      patternEncoding,
      caseInsensitive,
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

  public getMatchType(): IpsMatchType {
    return this.matchType;
  }

  public getPatternEncoding(): IpsPatternEncoding {
    return this.patternEncoding;
  }

  public getCaseInsensitive(): boolean {
    return this.caseInsensitive;
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

  private static assertRuntimeOptionsAreValid(
    id: string,
    pattern: RegexPattern,
    matchType: IpsMatchType,
    patternEncoding: IpsPatternEncoding,
    caseInsensitive: boolean,
  ): void {
    if (
      patternEncoding.getValue() === "IPS_PATTERN_ENCODING_HEX" &&
      matchType.getValue() === "IPS_MATCH_TYPE_REGEX"
    ) {
      throw new IpsSignatureConfigIsInvalidException(
        `IPS signature '${id}' cannot use hex encoding with regex match type`,
      );
    }

    if (
      patternEncoding.getValue() === "IPS_PATTERN_ENCODING_HEX" &&
      caseInsensitive
    ) {
      throw new IpsSignatureConfigIsInvalidException(
        `IPS signature '${id}' cannot use caseInsensitive with hex encoding`,
      );
    }

    if (
      patternEncoding.getValue() === "IPS_PATTERN_ENCODING_HEX" &&
      !IpsSignature.isValidHexPattern(pattern.getValue())
    ) {
      throw new IpsSignatureConfigIsInvalidException(
        `IPS signature '${id}' has invalid hex pattern`,
      );
    }
  }

  private static isValidHexPattern(pattern: string): boolean {
    const normalized = pattern.replace(/\s+/g, "");

    return (
      normalized.length > 0 &&
      normalized.length % 2 === 0 &&
      /^[0-9a-fA-F]+$/.test(normalized)
    );
  }
}
