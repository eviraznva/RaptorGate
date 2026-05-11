export class IdentityConfigIsInvalidException extends Error {
  constructor(reason: string) {
    super(`Identity configuration is invalid: ${reason}`);
    this.name = 'IdentityConfigIsInvalidException';
  }
}
