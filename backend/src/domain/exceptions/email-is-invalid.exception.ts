export class EmailIsInvalidException extends Error {
  constructor(email: string) {
    super(`The email address "${email}" is invalid.`);

    this.name = 'EmailIsInvalidException';
  }
}
