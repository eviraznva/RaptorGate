import { Permission } from './permission.entity.js';

export class Role {
  private constructor(
    private readonly id: string,
    private readonly name: string,
    private readonly description: string | null,
    private readonly permissions: Permission[],
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null = null,
    permissions: Permission[] = [],
  ): Role {
    return new Role(id, name, description, permissions);
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

  public getPermissions(): Permission[] {
    return this.permissions;
  }

  public hasPermission(permissionName: string): boolean {
    return this.permissions.some((p) => p.getName() === permissionName);
  }
}
