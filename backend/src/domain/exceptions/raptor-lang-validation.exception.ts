export class RaptorLangValidationException extends Error {
  constructor(message: string) {
    super(message);

    this.name = 'RaptorLangValidationException';
  }
}
