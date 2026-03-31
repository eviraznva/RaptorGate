import { RegexPatternIsInvalidException } from '../exceptions/regex-pattern-is-invalid.exception.js';

export class RegexPattern {
  private readonly value: string;

  private constructor(pattern: string) {
    this.value = pattern;
  }

  public static create(pattern: string): RegexPattern {
    if (!this.isValid(pattern)) {
      throw new RegexPatternIsInvalidException(pattern);
    }

    return new RegexPattern(pattern);
  }

  private static isValid(pattern: string): boolean {
    try {
      new RegExp(pattern);
      return true;
    } catch (e) {
      return false;
    }
  }

  public getValue(): string {
    return this.value;
  }
}
