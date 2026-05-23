import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { isIP } from 'node:net';

const ZONE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INTERFACE_NAME_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;

export interface PortalListenerSettingsInput {
  enabled: boolean;
  interfaceName: string | null;
  zoneId: string | null;
  bindAddress: string | null;
  bindPort: number;
}

export type IdentityAuthenticationTarget =
  | { kind: 'profile'; id: string }
  | { kind: 'sequence'; id: string };

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

    const interfaceName = normalizeNullable(input.interfaceName);
    const zoneId = normalizeNullable(input.zoneId);
    const bindAddress = normalizeNullable(input.bindAddress);

    if (interfaceName && !INTERFACE_NAME_PATTERN.test(interfaceName)) {
      throw new IdentityConfigIsInvalidException('portal listener interfaceName is invalid');
    }

    if (zoneId && !ZONE_ID_PATTERN.test(zoneId)) {
      throw new IdentityConfigIsInvalidException('portal listener zoneId must be a UUID');
    }

    if (bindAddress && isIP(bindAddress) === 0) {
      throw new IdentityConfigIsInvalidException('portal listener bindAddress must be an IP address');
    }

    return new PortalListenerSettings(
      input.enabled,
      interfaceName,
      zoneId,
      bindAddress,
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
    private portalAuthenticationTarget: IdentityAuthenticationTarget | null,
    private adminAuthenticationTarget: IdentityAuthenticationTarget | null,
    private updatedAt: Date | null,
    private updatedBy: string | null,
    private portalListener: PortalListenerSettings,
  ) {}

  public static create(
    portalAuthenticationProfileId: string | IdentityAuthenticationTarget | null,
    adminAuthenticationProfileId: string | IdentityAuthenticationTarget | null,
    updatedAt: Date | null,
    updatedBy: string | null,
    portalListener: PortalListenerSettingsInput | PortalListenerSettings = PortalListenerSettings.disabled(),
  ): IdentitySettings {
    return new IdentitySettings(
      normalizeTarget(portalAuthenticationProfileId),
      normalizeTarget(adminAuthenticationProfileId),
      updatedAt,
      normalizeNullable(updatedBy),
      portalListener instanceof PortalListenerSettings
        ? portalListener
        : PortalListenerSettings.create(portalListener),
    );
  }

  public getPortalAuthenticationProfileId(): string | null {
    return this.portalAuthenticationTarget?.kind === 'profile'
      ? this.portalAuthenticationTarget.id
      : null;
  }

  public getAdminAuthenticationProfileId(): string | null {
    return this.adminAuthenticationTarget?.kind === 'profile'
      ? this.adminAuthenticationTarget.id
      : null;
  }

  public getPortalAuthenticationTarget(): IdentityAuthenticationTarget | null {
    return this.portalAuthenticationTarget ? { ...this.portalAuthenticationTarget } : null;
  }

  public getAdminAuthenticationTarget(): IdentityAuthenticationTarget | null {
    return this.adminAuthenticationTarget ? { ...this.adminAuthenticationTarget } : null;
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

function normalizeTarget(
  value: string | IdentityAuthenticationTarget | null,
): IdentityAuthenticationTarget | null {
  if (typeof value === 'string') {
    const id = normalizeNullable(value);
    return id ? { kind: 'profile', id } : null;
  }
  if (!value) return null;

  const id = normalizeNullable(value.id);
  if (!id) {
    throw new IdentityConfigIsInvalidException('authentication target id is required');
  }
  if (value.kind !== 'profile' && value.kind !== 'sequence') {
    throw new IdentityConfigIsInvalidException('authentication target kind is invalid');
  }

  return { kind: value.kind, id };
}
