import { IpsMatchTypeIsInvalidException } from "../exceptions/ips-match-type-is-invalid.exception.js";

export type IpsMatchTypeType =
  | "IPS_MATCH_TYPE_LITERAL"
  | "IPS_MATCH_TYPE_REGEX";

export class IpsMatchType {
  private static readonly ALLOWED_VALUES: IpsMatchTypeType[] = [
    "IPS_MATCH_TYPE_LITERAL",
    "IPS_MATCH_TYPE_REGEX",
  ];

  private readonly value: IpsMatchTypeType;

  private constructor(matchType: IpsMatchTypeType) {
    this.value = matchType;
  }

  public static create(matchType: string): IpsMatchType {
    if (!IpsMatchType.isValidType(matchType)) {
      throw new IpsMatchTypeIsInvalidException(matchType);
    }

    return new IpsMatchType(matchType as IpsMatchTypeType);
  }

  private static isValidType(type: string): boolean {
    return IpsMatchType.ALLOWED_VALUES.includes(type as IpsMatchTypeType);
  }

  public getValue(): IpsMatchTypeType {
    return this.value;
  }
}
