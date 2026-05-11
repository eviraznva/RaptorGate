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
    private sniffed: boolean,
    private parentInterfaceId: string | null,
  ) {}

  public static create(
    id: string,
    zoneId: string,
    interfaceName: string,
    vlanId: number | null,
    status: ZoneInterfaceStatus,
    addresses: string[],
    createdAt: Date,
    sniffed: boolean = false,
    parentInterfaceId: string | null = null,
  ): ZoneInterface {
    return new ZoneInterface(
      id,
      zoneId,
      interfaceName,
      vlanId,
      status,
      addresses,
      createdAt,
      sniffed,
      parentInterfaceId,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getZoneId(): string {
    return this.zoneId;
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

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getAddresses(): string[] {
    return this.addresses;
  }

  public getSniffed(): boolean {
    return this.sniffed;
  }

  public getParentInterfaceId(): string | null {
    return this.parentInterfaceId;
  }

  public getKind(): "physical" | "vlan" {
    return this.vlanId === null ? "physical" : "vlan";
  }
}
