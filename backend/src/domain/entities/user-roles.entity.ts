export class UserRole {
  constructor(
    private readonly userId: string,
    private readonly roleId: string,
  ) {}

  static create(userId: string, roleId: string): UserRole {
    return new UserRole(userId, roleId);
  }

  public getUserId(): string {
    return this.userId;
  }

  public getRoleId(): string {
    return this.roleId;
  }
}
