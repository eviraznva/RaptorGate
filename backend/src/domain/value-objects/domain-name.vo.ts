import { DomainNameIsInvalidException } from "../exceptions/domain-name-is-invalid.exception";

export class DomainName {
  private readonly value: string;

  private constructor(domain: string) {
    this.value = domain;
  }

  public static create(domain: string): DomainName {
    if (!DomainName.isValid(domain)) {
      throw new DomainNameIsInvalidException(domain);
    }

    return new DomainName(domain);
  }

  private static isValid(domain: string): boolean {
    const domainRegex =
      /^(?=.{1,253}$)(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

    return domainRegex.test(domain);
  }

  public get getValue(): string {
    return this.value;
  }
}
