import { IpAddress } from '../value-objects/ip-address.vo.js';

// Runtime sesja identity. Nie wchodzi w config snapshot.
// Issue G utrwala aktywne sesje poza configiem dla replayu do firewalla.
// Minimum z Issue 3: sourceIp, username, createdAt, expiresAt.
// TODO(Issue H): macAddress moze pochodzic z portalu/DHCP snoopingu.
export class IdentitySession {
  private constructor(
    private readonly id: string,
    private readonly username: string,
    private readonly sourceIp: IpAddress,
    private readonly createdAt: Date,
    private expiresAt: Date,
    private groups: string[],
    private readonly nasIp: string,
    private readonly calledStationId: string,
    private readonly identityUserId: string,
    private readonly macAddress: string,
  ) {}

  public static create(
    id: string,
    username: string,
    sourceIp: IpAddress,
    createdAt: Date,
    expiresAt: Date,
    groups: string[] = [],
    nasIp = '127.0.0.1',
    calledStationId = 'raptorgate',
    identityUserId = username,
    macAddress = '00:00:00:00:00:00',
  ): IdentitySession {
    return new IdentitySession(
      id,
      username,
      sourceIp,
      createdAt,
      expiresAt,
      normalizeGroups(groups),
      nasIp,
      calledStationId,
      identityUserId,
      macAddress,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getUsername(): string {
    return this.username;
  }

  public getIdentityUserId(): string {
    return this.identityUserId;
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

  public getGroups(): string[] {
    return [...this.groups];
  }

  public getNasIp(): string {
    return this.nasIp;
  }

  public getCalledStationId(): string {
    return this.calledStationId;
  }

  public getMacAddress(): string {
    return this.macAddress;
  }

  public renew(newExpiresAt: Date): void {
    this.expiresAt = newExpiresAt;
  }

  public replaceGroups(groups: string[]): void {
    this.groups = normalizeGroups(groups);
  }

  public isExpiredAt(now: Date): boolean {
    return this.expiresAt.getTime() <= now.getTime();
  }
}

function normalizeGroups(groups: string[]): string[] {
  const normalized: string[] = [];
  for (const raw of groups) {
    const group = raw.trim();
    if (group && !normalized.includes(group)) {
      normalized.push(group);
    }
  }
  return normalized;
}
