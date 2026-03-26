import { SemanticVersionIsInvalidException } from '../exceptions/semantic-version-is-invalid.exception.js';

export class SemanticVersion {
  private readonly value: string;

  private constructor(version: string) {
    this.value = version;
  }

  public static create(version: string): SemanticVersion {
    if (!this.isValid(version)) {
      throw new SemanticVersionIsInvalidException(version);
    }

    return new SemanticVersion(version);
  }

  private static isValid(version: string): boolean {
    const semanticVersionRegex =
      /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][a-zA-Z0-9-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][a-zA-Z0-9-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

    return semanticVersionRegex.test(version);
  }

  public getValue(): string {
    return this.value;
  }
}
