import { PriorityIsInvalidException } from '../exceptions/priority-is-invalid.exception';

export class Priority {
  private readonly value: number;

  private constructor(priority: number) {
    this.value = priority;
  }

  public static create(priority: number): Priority {
    if (!this.isValid(priority)) {
      throw new PriorityIsInvalidException(priority);
    }

    return new Priority(priority);
  }

  private static isValid(priority: number): boolean {
    if (priority >= 1 && priority <= 100) {
      return true;
    } else {
      return false;
    }
  }

  public getValue(): number {
    return this.value;
  }
}
