export class AuthenticationUnavailableException extends Error {
  constructor(message = 'Authentication provider is unavailable.') {
    super(message);
    this.name = 'AuthenticationUnavailableException';
  }
}
