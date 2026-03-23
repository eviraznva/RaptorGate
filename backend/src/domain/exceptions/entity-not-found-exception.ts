export class EntityNotFoundException extends Error {
  constructor(entityName: string, identifier: string) {
    super(`${entityName} with identifier "${identifier}" was not found.`);

    this.name = 'EntityNotFoundException';
  }
}
