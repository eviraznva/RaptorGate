export class SemanticVersionIsInvalidException extends Error {
  constructor(version: string) {
    super(`Invalid semantic version format: ${version}`);

    this.name = 'SemanticVersionIsInvalidException';
  }
}
