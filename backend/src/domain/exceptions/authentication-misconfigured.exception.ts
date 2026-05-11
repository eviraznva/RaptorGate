export class AuthenticationMisconfiguredException extends Error {
  constructor(message = 'Authentication profile is misconfigured.') {
    super(message);
    this.name = 'AuthenticationMisconfiguredException';
  }
}
