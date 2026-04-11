export class PriorityIsInvalidException extends Error {
  constructor(priority: number) {
    super(
      `The priority value "${priority}" is invalid. It must be between 1 and 100.`,
    );

    this.name = 'PriorityIsInvalidException';
  }
}
