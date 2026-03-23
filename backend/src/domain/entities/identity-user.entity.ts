import { UserSource } from '../value-objects/user-source.vo';
import { Email } from '../value-objects/email.vo';

export class IdentityUser {
  private constructor(
    private readonly id: string,
    private username: string,
    private displayName: string,
    private source: UserSource,
    private externalId: string,
    private email: Email,
    private lastSeenAt: Date | null,
    private readonly createdAt: Date,
    private updatedAt: Date,
  ) {}

  public static create(
    id: string,
    username: string,
    displayName: string,
    source: UserSource,
    externalId: string,
    email: Email,
    lastSeenAt: Date | null,
    createdAt: Date,
    updatedAt: Date,
  ): IdentityUser {
    return new IdentityUser(
      id,
      username,
      displayName,
      source,
      externalId,
      email,
      lastSeenAt,
      createdAt,
      updatedAt,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getUsername(): string {
    return this.username;
  }

  public getDisplayName(): string {
    return this.displayName;
  }

  public getSource(): UserSource {
    return this.source;
  }

  public getExternalId(): string {
    return this.externalId;
  }

  public getEmail(): Email {
    return this.email;
  }

  public getLastSeenAt(): Date | null {
    return this.lastSeenAt;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  public setLastSeenAt(lastSeenAt: Date): void {
    this.lastSeenAt = lastSeenAt;
  }
}
