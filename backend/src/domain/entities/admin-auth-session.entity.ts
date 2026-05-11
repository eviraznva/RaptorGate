import { Role } from '../enums/role.enum.js';

export type AdminAuthProvider = 'radius' | 'ldap';
export type AdminAuthSessionRole = 'super_admin' | 'admin' | 'operator' | 'viewer';

export class AdminAuthSession {
  private constructor(
    private readonly id: string,
    private readonly username: string,
    private readonly provider: AdminAuthProvider,
    private readonly authProfileId: string,
    private readonly externalId: string,
    private readonly roles: AdminAuthSessionRole[],
    private refreshTokenHash: string,
    private refreshTokenExpiry: Date,
    private readonly createdAt: Date,
    private lastSeenAt: Date,
    private revokedAt: Date | null,
  ) {}

  public static create(
    id: string,
    username: string,
    provider: AdminAuthProvider,
    authProfileId: string,
    externalId: string,
    roles: AdminAuthSessionRole[],
    refreshTokenHash: string,
    refreshTokenExpiry: Date,
    createdAt: Date,
    lastSeenAt: Date,
    revokedAt: Date | null,
  ): AdminAuthSession {
    requireText(id, 'admin auth session id');
    requireText(username, 'admin auth session username');
    requireText(authProfileId, 'admin auth session authProfileId');
    requireText(externalId, 'admin auth session externalId');
    requireText(refreshTokenHash, 'admin auth session refreshTokenHash');
    if (provider !== 'radius' && provider !== 'ldap') {
      throw new Error('admin auth session provider is invalid');
    }
    if (roles.length === 0) {
      throw new Error('admin auth session requires at least one role');
    }
    for (const role of roles) {
      if (![Role.SuperAdmin, Role.Admin, Role.Operator, Role.Viewer].includes(role as Role)) {
        throw new Error('admin auth session role is invalid');
      }
    }

    return new AdminAuthSession(
      id,
      username,
      provider,
      authProfileId,
      externalId,
      [...roles],
      refreshTokenHash,
      refreshTokenExpiry,
      createdAt,
      lastSeenAt,
      revokedAt,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getUsername(): string {
    return this.username;
  }

  public getProvider(): AdminAuthProvider {
    return this.provider;
  }

  public getAuthProfileId(): string {
    return this.authProfileId;
  }

  public getExternalId(): string {
    return this.externalId;
  }

  public getRoles(): AdminAuthSessionRole[] {
    return [...this.roles];
  }

  public getRefreshTokenHash(): string {
    return this.refreshTokenHash;
  }

  public getRefreshTokenExpiry(): Date {
    return this.refreshTokenExpiry;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getLastSeenAt(): Date {
    return this.lastSeenAt;
  }

  public getRevokedAt(): Date | null {
    return this.revokedAt;
  }

  public isRevoked(): boolean {
    return this.revokedAt !== null;
  }

  public touch(lastSeenAt: Date): void {
    this.lastSeenAt = lastSeenAt;
  }

  public rotateRefreshToken(refreshTokenHash: string, refreshTokenExpiry: Date): void {
    requireText(refreshTokenHash, 'admin auth session refreshTokenHash');
    this.refreshTokenHash = refreshTokenHash;
    this.refreshTokenExpiry = refreshTokenExpiry;
  }

  public revoke(revokedAt: Date): void {
    this.revokedAt = revokedAt;
  }
}

function requireText(value: string, field: string): void {
  if (!value.trim()) {
    throw new Error(`${field} is required`);
  }
}
