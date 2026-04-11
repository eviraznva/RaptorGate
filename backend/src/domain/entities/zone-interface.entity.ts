export class ZoneInterface {
  private constructor(
    private readonly id: string,
    private interfaceName: string,
    private vlanId: number,
    private readonly createdAt: Date,
  ) {}

  public static create(
    id: string,
    interfaceName: string,
    vlanId: number,
    createdAt: Date,
  ): ZoneInterface {
    return new ZoneInterface(id, interfaceName, vlanId, createdAt);
  }

  public getId(): string {
    return this.id;
  }

  public getInterfaceName(): string {
    return this.interfaceName;
  }

  public getVlanId(): number {
    return this.vlanId;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }
}
