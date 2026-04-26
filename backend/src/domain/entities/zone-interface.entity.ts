export type ZoneInterfaceStatus =
  | "unspecified"
  | "active"
  | "inactive"
  | "missing"
  | "unknown";

export class ZoneInterface {
  private constructor(
    private readonly id: string,
    private readonly zoneId: string,
    private interfaceName: string,
    private vlanId: number | null,
    private status: ZoneInterfaceStatus,
    private addresses: string[],
    private readonly createdAt: Date,
  ) {}

  public static create(
    id: string,
    zoneId: string,
    interfaceName: string,
    vlanId: number | null,
    status: ZoneInterfaceStatus,
    addresses: string[],
    createdAt: Date,
  ): ZoneInterface {
    return new ZoneInterface(
      id,
      zoneId,
      interfaceName,
      vlanId,
      status,
      addresses,
      createdAt,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getInterfaceName(): string {
    return this.interfaceName;
  }

  public getVlanId(): number | null {
    return this.vlanId;
  }

  public getStatus(): ZoneInterfaceStatus {
    return this.status;
  }

  public getZoneId(): string {
    return this.zoneId;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getAddresses(): string[] {
    return this.addresses;
  }
}
