import { SecretIsInvalidException } from '../exceptions/secret-is-invalid.exception.js';

export class SecretValue {
  private constructor(private readonly value: string) {}

  public static create(value: string): SecretValue {
    if (value.length === 0) {
      throw new SecretIsInvalidException('secret value is required');
    }

    if (Buffer.byteLength(value, 'utf8') > 4096) {
      throw new SecretIsInvalidException('secret value must be 4096 bytes or smaller');
    }

    return new SecretValue(value);
  }

  public getValue(): string {
    return this.value;
  }

  public toJSON(): string {
    return '[redacted]';
  }
}
