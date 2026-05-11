import { RegexPatternIsInvalidException } from "../exceptions/regex-pattern-is-invalid.exception.js";

export class RegexPattern {
  private readonly value: string;

  private constructor(pattern: string) {
    this.value = pattern;
  }

  public static create(pattern: string): RegexPattern {
    if (!RegexPattern.isValid(pattern)) {
      throw new RegexPatternIsInvalidException(pattern);
    }

    return new RegexPattern(pattern);
  }

  public static isValid(pattern: string): boolean {
    return pattern.length > 0;
  }

  public getValue(): string {
    return this.value;
  }
}
