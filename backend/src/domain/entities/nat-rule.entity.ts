import { IpAddress } from '../value-objects/ip-address.vo';
import { Priority } from '../value-objects/priority.vo';
import { NatType } from '../value-objects/nat-type.vo';
import { Port } from '../value-objects/port.vo';

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
}
