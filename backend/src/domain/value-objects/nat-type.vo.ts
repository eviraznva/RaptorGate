import { NatTypeIsInvalidException } from '../exceptions/nat-type-is-invalid.exception.js';

export type NatTypeType = 'SNAT' | 'DNAT' | 'PAT';

export class NatType {
  private static readonly ALLOWED_VALUES: NatTypeType[] = [
    'SNAT',
    'DNAT',
    'PAT',
  ];

  private readonly value: NatTypeType;

  private constructor(type: NatTypeType) {
    this.value = type;
  }

  public static create(type: string): NatType {
    if (!this.isValidType(type)) {
      throw new NatTypeIsInvalidException(type);
    }

    return new NatType(type as NatTypeType);
  }

  private static isValidType(type: string): boolean {
    return NatType.ALLOWED_VALUES.includes(type as NatTypeType);
  }

  public getValue(): NatTypeType {
    return this.value;
  }
}
