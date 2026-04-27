import { IpsPatternEncodingIsInvalidException } from "../exceptions/ips-pattern-encoding-is-invalid.exception.js";

export type IpsPatternEncodingType =
  | "IPS_PATTERN_ENCODING_TEXT"
  | "IPS_PATTERN_ENCODING_HEX";

export class IpsPatternEncoding {
  private static readonly ALLOWED_VALUES: IpsPatternEncodingType[] = [
    "IPS_PATTERN_ENCODING_TEXT",
    "IPS_PATTERN_ENCODING_HEX",
  ];

  private readonly value: IpsPatternEncodingType;

  private constructor(patternEncoding: IpsPatternEncodingType) {
    this.value = patternEncoding;
  }

  public static create(patternEncoding: string): IpsPatternEncoding {
    if (!IpsPatternEncoding.isValidType(patternEncoding)) {
      throw new IpsPatternEncodingIsInvalidException(patternEncoding);
    }

    return new IpsPatternEncoding(patternEncoding as IpsPatternEncodingType);
  }

  private static isValidType(type: string): boolean {
    return IpsPatternEncoding.ALLOWED_VALUES.includes(
      type as IpsPatternEncodingType,
    );
  }

  public getValue(): IpsPatternEncodingType {
    return this.value;
  }
}
