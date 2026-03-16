export class AccessTokenIsInvalidException extends Error {
  constructor() {
    super('Access token is invalid or expired.');

    this.name = 'AccessTokenIsInvalidException';
  }
}
