export class AuthenticationRejectedException extends Error {
  constructor(message = 'Invalid username or password.') {
    super(message);
    this.name = 'AuthenticationRejectedException';
  }
}
