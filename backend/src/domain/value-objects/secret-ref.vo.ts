import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';

export const SECRET_REF_PATTERN =
  /^(env:[A-Z_][A-Z0-9_]*|secret:\/\/[a-z0-9-]+\/[a-z0-9-]+\/[a-z0-9-]+)$/;

export class SecretRef {
  private constructor(private readonly value: string) {}

  public static create(value: string): SecretRef {
    const normalized = value.trim();

    if (!SECRET_REF_PATTERN.test(normalized)) {
      throw new IdentityConfigIsInvalidException(
        'secret ref must use env:NAME or secret://scope/type/name',
      );
    }

    return new SecretRef(normalized);
  }

  public getValue(): string {
    return this.value;
  }
}
