export class AtLeastOneFieldRequiredException extends Error {
  constructor() {
    super('At least one field is required.');

    this.name = 'AtLeastOneFieldRequiredException';
  }
}
