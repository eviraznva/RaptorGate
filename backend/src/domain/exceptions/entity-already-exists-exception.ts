export class EntityAlreadyExistsException extends Error {
  constructor(entityName: string, field: string, value: string) {
    super(`${entityName} with field:${field} value:"${value}" already exists.`);

    this.name = 'EntityAlreadyExistsException';
  }
}
