import { Role } from './role.entity.js';

export class User {
  private constructor(
    private readonly id: string,
    private username: string,
    private passwordHash: string,
    private refreshToken: string | null,
    private refreshTokenExpiry: Date | null,
    private recoveryToken: string | null,
    private isFirstLogin: boolean,
    private showRecoveryToken: boolean,
    private readonly createdAt: Date,
    private updatedAt: Date,
    private roles: Role[],
  ) {}

  public static create(
    id: string,
    username: string,
    passwordHash: string,
    refreshToken: string | null,
    refreshTokenExpiry: Date | null,
    recoveryToken: string | null,
    isFirstLogin: boolean,
    showRecoveryToken: boolean,
    createdAt: Date,
    updatedAt: Date,
    roles: Role[] = [],
  ): User {
    return new User(
      id,
      username,
      passwordHash,
      refreshToken,
      refreshTokenExpiry,
      recoveryToken,
      isFirstLogin,
      showRecoveryToken,
      createdAt,
      updatedAt,
      roles,
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

  public getRefreshToken(): string | null {
    return this.refreshToken;
  }

  public getRefreshTokenExpiry(): Date | null {
    return this.refreshTokenExpiry;
  }

  public getRoles(): Role[] {
    return this.roles;
  }

  public getRecoveryToken(): string | null {
    return this.recoveryToken;
  }

  public getIsFirstLogin(): boolean {
    return this.isFirstLogin;
  }

  public getShowRecoveryToken(): boolean {
    return this.showRecoveryToken;
  }

  public hasRole(roleName: string): boolean {
    return this.roles.some((r) => r.getName() === roleName);
  }

  public hasPermission(permissionName: string): boolean {
    return this.roles.some((r) => r.hasPermission(permissionName));
  }

  public setUsername(username: string): void {
    this.username = username;
  }

  public setPasswordHash(passwordHash: string): void {
    this.passwordHash = passwordHash;
  }

  public setRefreshToken(refreshToken: string | null): void {
    this.refreshToken = refreshToken;
  }

  public setRefreshTokenExpiry(refreshTokenExpiry: Date | null): void {
    this.refreshTokenExpiry = refreshTokenExpiry;
  }

  public setRoles(roles: Role[]): void {
    this.roles = roles;
  }

  public setUpdatedAt(updatedAt: Date): void {
    this.updatedAt = updatedAt;
  }

  public setRecoveryToken(recoveryToken: string | null): void {
    this.recoveryToken = recoveryToken;
  }

  public setIsFirstLogin(isFirstLogin: boolean): void {
    this.isFirstLogin = isFirstLogin;
  }

  public setShowRecoveryToken(showRecoveryToken: boolean): void {
    this.showRecoveryToken = showRecoveryToken;
  }
}
