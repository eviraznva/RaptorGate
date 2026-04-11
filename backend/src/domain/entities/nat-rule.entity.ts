import { IpAddress } from '../value-objects/ip-address.vo.js';
import { NatType } from '../value-objects/nat-type.vo.js';
import { Port } from '../value-objects/port.vo.js';
import { Priority } from '../value-objects/priority.vo.js';

export class NatRule {
  private constructor(
    private readonly id: string,
    private type: NatType,
    private isActive: boolean,
    private sourceIp: IpAddress | null,
    private destinationIp: IpAddress | null,
    private sourcePort: Port | null,
    private destinationPort: Port | null,
    private translatedIp: IpAddress | null,
    private translatedPort: Port | null,
    private priority: Priority,
    private readonly createdAt: Date,
    private updatedAt: Date,
  ) {}

  public static create(
    id: string,
    type: NatType,
    isActive: boolean,
    sourceIp: IpAddress | null,
    destinationIp: IpAddress | null,
    sourcePort: Port | null,
    destinationPort: Port | null,
    translatedIp: IpAddress | null,
    translatedPort: Port | null,
    priority: Priority,
    createdAt: Date,
    updatedAt: Date,
  ): NatRule {
    return new NatRule(
      id,
      type,
      isActive,
      sourceIp,
      destinationIp,
      sourcePort,
      destinationPort,
      translatedIp,
      translatedPort,
      priority,
      createdAt,
      updatedAt,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getType(): NatType {
    return this.type;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getSourceIp(): IpAddress | null {
    return this.sourceIp;
  }

  public getDestinationIp(): IpAddress | null {
    return this.destinationIp;
  }

  public getSourcePort(): Port | null {
    return this.sourcePort;
  }

  public getDestinationPort(): Port | null {
    return this.destinationPort;
  }

  public getTranslatedIp(): IpAddress | null {
    return this.translatedIp;
  }

  public getTranslatedPort(): Port | null {
    return this.translatedPort;
  }

  public getPriority(): Priority {
    return this.priority;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  public setType(type: string): void {
    this.type = NatType.create(type);
  }

  public setIsActive(isActive: boolean): void {
    this.isActive = isActive;
  }

  public setPriority(priority: number): void {
    this.priority = Priority.create(priority);
  }

  public setSourceIp(sourceIp: string | null): void {
    this.sourceIp = sourceIp === null ? null : IpAddress.create(sourceIp);
  }

  public setDestinationIp(destinationIp: string | null): void {
    this.destinationIp =
      destinationIp === null ? null : IpAddress.create(destinationIp);
  }

  public setSourcePort(sourcePort: number | null): void {
    this.sourcePort = sourcePort === null ? null : Port.create(sourcePort);
  }

  public setDestinationPort(destinationPort: number | null): void {
    this.destinationPort =
      destinationPort === null ? null : Port.create(destinationPort);
  }

  public setTranslatedIp(translatedIp: string | null): void {
    this.translatedIp =
      translatedIp === null ? null : IpAddress.create(translatedIp);
  }

  public setTranslatedPort(translatedPort: number | null): void {
    this.translatedPort =
      translatedPort === null ? null : Port.create(translatedPort);
  }

  public setUpdatedAt(updatedAt: Date): void {
    this.updatedAt = updatedAt;
  }
}
