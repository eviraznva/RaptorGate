export class IdentitySettings {
  // TODO(Issue VPN): add vpnAuthenticationProfileId when VPN auth flow exists.
  private constructor(
    private portalAuthenticationProfileId: string | null,
    private adminAuthenticationProfileId: string | null,
    private updatedAt: Date | null,
    private updatedBy: string | null,
  ) {}

  public static create(
    portalAuthenticationProfileId: string | null,
    adminAuthenticationProfileId: string | null,
    updatedAt: Date | null,
    updatedBy: string | null,
  ): IdentitySettings {
    return new IdentitySettings(
      normalizeNullable(portalAuthenticationProfileId),
      normalizeNullable(adminAuthenticationProfileId),
      updatedAt,
      normalizeNullable(updatedBy),
    );
  }

  public getPortalAuthenticationProfileId(): string | null {
    return this.portalAuthenticationProfileId;
  }

  public getAdminAuthenticationProfileId(): string | null {
    return this.adminAuthenticationProfileId;
  }

  public getUpdatedAt(): Date | null {
    return this.updatedAt;
  }

  public getUpdatedBy(): string | null {
    return this.updatedBy;
  }
}

function normalizeNullable(value: string | null): string | null {
  const normalized = value?.trim() ?? '';
  return normalized ? normalized : null;
}
