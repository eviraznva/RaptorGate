export class SecretReferenceMissingException extends Error {
  constructor(ref: string) {
    super(`Managed secret reference "${ref}" does not exist.`);
    this.name = 'SecretReferenceMissingException';
  }
}
