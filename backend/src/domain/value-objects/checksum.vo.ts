import { ChecksumIsInvalidException } from '../exceptions/checksum-is-invalid.exception.js';

export class Checksum {
  private readonly value: string;

  private constructor(checksum: string) {
    this.value = checksum;
  }

  public static create(checksum: string): Checksum {
    if (!this.isValid(checksum)) {
      throw new ChecksumIsInvalidException(checksum);
    }

    return new Checksum(checksum);
  }

  private static isValid(checksum: string): boolean {
    const sha256Regex = /^[a-fA-F0-9]{64}$/;
    return sha256Regex.test(checksum);
  }

  public getValue(): string {
    return this.value;
  }
}
