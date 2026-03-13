import { IpAddressIsInvalidException } from '../exceptions/ip-address-is-invalid.exception';

export class IpAddress {
  private readonly value: string;

  private constructor(ip: string) {
    this.value = ip;
  }

  public static create(ip: string): IpAddress {
    if (!this.isValid(ip)) {
      throw new IpAddressIsInvalidException(ip);
    }

    return new IpAddress(ip);
  }

  private static isValidIPv4(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;

    return parts.every((part) => {
      const num = parseInt(part, 10);
      return !isNaN(num) && num >= 0 && num <= 255 && part === num.toString();
    });
  }

  private static isValidIPv6Group(group: string): boolean {
    return /^[0-9a-fA-F]{1,4}$/.test(group);
  }

  private static isValidIPv6(ip: string): boolean {
    if (ip.includes('::')) {
      const parts = ip.split('::');
      if (parts.length > 2) return false;
      const left = parts[0] ? parts[0].split(':') : [];
      const right = parts[1] ? parts[1].split(':') : [];
      return (
        left.length + right.length <= 8 &&
        [...left, ...right].every((g) => IpAddress.isValidIPv6Group(g))
      );
    }
    const groups = ip.split(':');
    return (
      groups.length === 8 && groups.every((g) => IpAddress.isValidIPv6Group(g))
    );
  }

  public static isValid(ip: string): boolean {
    return IpAddress.isValidIPv4(ip) || IpAddress.isValidIPv6(ip);
  }

  public get getValue(): string {
    return this.value;
  }
}
