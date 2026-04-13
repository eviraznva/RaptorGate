import { DomainName } from "../value-objects/domain-name.vo";

export class DnsBlacklistEntry {
  private constructor(
    private readonly id: string,
    private domain: DomainName,
    private reason: string,
    private isActive: boolean,
    private readonly createdAt: Date,
    private readonly createdBy: string,
  ) {}

  public static create(
    id: string,
    domain: DomainName,
    reason: string,
    isActive: boolean,
    createdAt: Date,
    createdBy: string,
  ): DnsBlacklistEntry {
    return new DnsBlacklistEntry(
      id,
      domain,
      reason,
      isActive,
      createdAt,
      createdBy,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getDomain(): string {
    return this.domain.getValue;
  }

  public getReason(): string {
    return this.reason;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getCreatedBy(): string {
    return this.createdBy;
  }
}
