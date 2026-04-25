import { IpAddress } from '../value-objects/ip-address.vo.js';

// Runtime sesja identity (ADR 0002). Trzymana w pamieci backendu i syncowana
// do firewalla (Issue 2). Nie wchodzi w config snapshot ani persistence.
// Minimum z Issue 3: sourceIp, username, createdAt, expiresAt.
// TODO(Issue 4): grupy LDAP dologa sie po zresolvowaniu.
// TODO(Issue 7): macAddress moze pochodzic z portalu/DHCP snoopingu.
export class IdentitySession {
  private constructor(
    private readonly id: string,
    private readonly username: string,
    private readonly sourceIp: IpAddress,
    private readonly createdAt: Date,
    private expiresAt: Date,
  ) {}

  public static create(
    id: string,
    username: string,
    sourceIp: IpAddress,
    createdAt: Date,
    expiresAt: Date,
  ): IdentitySession {
    return new IdentitySession(id, username, sourceIp, createdAt, expiresAt);
  }

  public getId(): string {
    return this.id;
  }

  public getUsername(): string {
    return this.username;
  }

  public getSourceIp(): IpAddress {
    return this.sourceIp;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getExpiresAt(): Date {
    return this.expiresAt;
  }

  public renew(newExpiresAt: Date): void {
    this.expiresAt = newExpiresAt;
  }

  public isExpiredAt(now: Date): boolean {
    return this.expiresAt.getTime() <= now.getTime();
  }
}
