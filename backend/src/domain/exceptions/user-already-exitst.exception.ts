export class UserAlreadyExistsException extends Error {
  constructor() {
    super(`User with this email or username already exists`);

    this.name = 'UserAlreadyExistsException';
  }
}
