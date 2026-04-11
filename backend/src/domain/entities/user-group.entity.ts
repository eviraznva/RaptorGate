import { UserSource } from '../value-objects/user-source.vo.js';

export class UserGroup {
  private constructor(
    private readonly id: string,
    private name: string,
    private description: string | null,
    private source: UserSource,
    private readonly createdAt: Date,
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null,
    source: UserSource,
    createdAt: Date,
  ): UserGroup {
    return new UserGroup(id, name, description, source, createdAt);
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

  public getSource(): UserSource {
    return this.source;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }
}
