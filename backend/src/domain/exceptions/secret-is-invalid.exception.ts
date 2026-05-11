export class SecretIsInvalidException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecretIsInvalidException';
  }
}
