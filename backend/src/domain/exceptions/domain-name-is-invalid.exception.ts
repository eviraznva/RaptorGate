export class DomainNameIsInvalidException extends Error {
  constructor(domain: string) {
    super(`Invalid domain format ${domain}`);

    this.name = "DomainNameIsInvalidException";
  }
}
