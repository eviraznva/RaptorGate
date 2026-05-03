import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';

export interface PortalListenerSettingsInput {
  enabled: boolean;
  interfaceName: string | null;
  zoneId: string | null;
  bindAddress: string | null;
  bindPort: number;
}

export class PortalListenerSettings {
  private constructor(
    private readonly enabled: boolean,
    private readonly interfaceName: string | null,
    private readonly zoneId: string | null,
    private readonly bindAddress: string | null,
    private readonly bindPort: number,
  ) {}

  public static disabled(): PortalListenerSettings {
    return PortalListenerSettings.create({
      enabled: false,
      interfaceName: null,
      zoneId: null,
      bindAddress: null,
      bindPort: 443,
    });
  }

  public static create(input: PortalListenerSettingsInput): PortalListenerSettings {
    if (!Number.isInteger(input.bindPort) || input.bindPort < 1 || input.bindPort > 65535) {
      throw new IdentityConfigIsInvalidException('portal listener bindPort must be between 1 and 65535');
    }

    return new PortalListenerSettings(
      input.enabled,
      normalizeNullable(input.interfaceName),
      normalizeNullable(input.zoneId),
      normalizeNullable(input.bindAddress),
      input.bindPort,
    );
  }

  public getEnabled(): boolean {
    return this.enabled;
  }

  public getInterfaceName(): string | null {
    return this.interfaceName;
  }

  public getZoneId(): string | null {
    return this.zoneId;
  }

  public getBindAddress(): string | null {
    return this.bindAddress;
  }

  public getBindPort(): number {
    return this.bindPort;
  }
}

export class IdentitySettings {
  // TODO(Issue VPN): add vpnAuthenticationProfileId when VPN auth flow exists.
  private constructor(
    private portalAuthenticationProfileId: string | null,
    private adminAuthenticationProfileId: string | null,
    private updatedAt: Date | null,
    private updatedBy: string | null,
    private portalListener: PortalListenerSettings,
  ) {}

  public static create(
    portalAuthenticationProfileId: string | null,
    adminAuthenticationProfileId: string | null,
    updatedAt: Date | null,
    updatedBy: string | null,
    portalListener: PortalListenerSettingsInput | PortalListenerSettings = PortalListenerSettings.disabled(),
  ): IdentitySettings {
    return new IdentitySettings(
      normalizeNullable(portalAuthenticationProfileId),
      normalizeNullable(adminAuthenticationProfileId),
      updatedAt,
      normalizeNullable(updatedBy),
      portalListener instanceof PortalListenerSettings
        ? portalListener
        : PortalListenerSettings.create(portalListener),
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

  public getPortalListener(): PortalListenerSettings {
    return this.portalListener;
  }
}

function normalizeNullable(value: string | null): string | null {
  const normalized = value?.trim() ?? '';
  return normalized ? normalized : null;
}
