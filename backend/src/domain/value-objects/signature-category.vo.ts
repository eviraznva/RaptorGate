import { IpsSignatureCategoryIsInvalidException } from '../exceptions/ips-signature-category-is-invalid.exception.js';

export type IpsSignatureCategoryType =
  | 'sqli'
  | 'xss'
  | 'shellcode'
  | 'path-traversal'
  | 'rce'
  | 'lfi'
  | 'rfi'
  | 'other';

export class SignatureCategory {
  private static readonly ALLOWED_VALUES: IpsSignatureCategoryType[] = [
    'sqli',
    'xss',
    'shellcode',
    'path-traversal',
    'rce',
    'lfi',
    'rfi',
    'other',
  ];

  private readonly value: IpsSignatureCategoryType;

  private constructor(category: IpsSignatureCategoryType) {
    this.value = category;
  }

  public static create(category: IpsSignatureCategoryType): SignatureCategory {
    if (!this.isValidType(category)) {
      throw new IpsSignatureCategoryIsInvalidException(category);
    }

    return new SignatureCategory(category);
  }

  private static isValidType(type: string): boolean {
    return SignatureCategory.ALLOWED_VALUES.includes(
      type as IpsSignatureCategoryType,
    );
  }

  public getValue(): IpsSignatureCategoryType {
    return this.value;
  }
}
