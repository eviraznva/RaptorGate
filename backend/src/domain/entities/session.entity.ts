import { IpAddress } from '../value-objects/ip-address.vo';

export class Session {
  private constructor(
    private readonly id: string,
    private ipAddress: IpAddress,
    private userAgent: string,
    private isActive: boolean,
    private readonly createdAt: Date,
    private expiresAt: Date,
    private revokedAt: Date | null,
  ) {}

  public static create(
    id: string,
    ipAddress: IpAddress,
    userAgent: string,
    isActive: boolean,
    createdAt: Date,
    expiresAt: Date,
    revokedAt: Date | null,
  ): Session {
    return new Session(
      id,
      ipAddress,
      userAgent,
      isActive,
      createdAt,
      expiresAt,
      revokedAt,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getIpAddress(): IpAddress {
    return this.ipAddress;
  }

  public getUserAgent(): string {
    return this.userAgent;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getExpiresAt(): Date {
    return this.expiresAt;
  }

  public getRevokedAt(): Date | null {
    return this.revokedAt;
  }

  public revoke(revokedAt: Date): void {
    this.revokedAt = revokedAt;
  }
}
