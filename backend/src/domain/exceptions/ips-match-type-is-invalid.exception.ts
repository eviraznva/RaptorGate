export class IpsMatchTypeIsInvalidException extends Error {
  constructor(matchType: string) {
    super(`IPS match type '${matchType}' is invalid`);

    this.name = "IpsMatchTypeIsInvalidException";
  }
}
