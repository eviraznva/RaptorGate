export class ZoneInterface {
  private constructor(
    private readonly id: string,
    private readonly zoneId: string,
    private interfaceName: string,
    private vlanId: number | null,
    private readonly createdAt: Date,
  ) {}

  public static create(
    id: string,
    zoneId: string,
    interfaceName: string,
    vlanId: number | null,
    createdAt: Date,
  ): ZoneInterface {
    return new ZoneInterface(id, zoneId, interfaceName, vlanId, createdAt);
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

  public getCreatedAt(): Date {
    return this.createdAt;
  }
}
