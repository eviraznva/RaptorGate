import { EmailIsInvalidException } from '../exceptions/email-is-invalid.exception.js';

export class Email {
  private readonly value: string;

  private constructor(email: string) {
    this.value = email;
  }

  public static create(email: string): Email {
    if (!this.isValid(email)) throw new EmailIsInvalidException(email);

    return new Email(email);
  }

  private static isValid(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  public get getValue(): string {
    return this.value;
  }
}
