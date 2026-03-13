import { Role } from '../enums/role.enum';

export class User {
  private constructor(
    private readonly id: string,
    private username: string,
    private passwordHash: string,
    private refreshToken: string | null,
    private roles: Role,
    private readonly createdAt: Date,
    private updatedAt: Date,
  ) {}

  public static create(
    id: string,
    username: string,
    passwordHash: string,
    refreshToken: string | null,
    roles: Role,
    createdAt: Date,
    updatedAt: Date,
  ): User {
    return new User(
      id,
      username,
      passwordHash,
      refreshToken,
      roles,
      createdAt,
      updatedAt,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getUsername(): string {
    return this.username;
  }

  public getPasswordHash(): string {
    return this.passwordHash;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  public getRole(): Role {
    return this.roles;
  }

  public getRefreshToken(): string | null {
    return this.refreshToken;
  }

  public setUsername(username: string): void {
    this.username = username;
  }

  public setPasswordHash(passwordHash: string): void {
    this.passwordHash = passwordHash;
  }

  public setRefreshToken(refreshToken: string): void {
    this.refreshToken = refreshToken;
  }
}
