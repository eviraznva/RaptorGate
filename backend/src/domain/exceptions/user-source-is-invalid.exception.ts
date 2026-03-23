export class UserSourceIsInvalidException extends Error {
  constructor(sourceType: string) {
    super(
      `The user source type "${sourceType}" is invalid. Allowed values are: raiuds, actice-directory, local.`,
    );
    this.name = 'UserSourceIsInvalidException';
  }
}
