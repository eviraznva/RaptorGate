export class Permission {
  private constructor(
    private readonly id: string,
    private readonly name: string,
    private readonly description: string | null,
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null = null,
  ): Permission {
    return new Permission(id, name, description);
  }

  public getId(): string {
    return this.id;
  }

  public getName(): string {
    return this.name;
  }

  public getDescription(): string | null {
    return this.description;
  }
}
