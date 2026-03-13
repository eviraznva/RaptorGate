export class Zone {
  private constructor(
    private readonly id: string,
    private name: string,
    private description: string | null,
    private isActive: boolean,
    private readonly createdAt: Date,
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null,
    isActive: boolean,
    createdAt: Date,
  ): Zone {
    return new Zone(id, name, description, isActive, createdAt);
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

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }
}
