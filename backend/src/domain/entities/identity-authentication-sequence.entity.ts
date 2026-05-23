import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';

export class IdentityAuthenticationSequence {
  private constructor(
    private readonly id: string,
    private readonly name: string,
    private readonly description: string | null,
    private readonly isActive: boolean,
    private readonly profileIds: string[],
    private readonly exitOnReject: boolean,
    private readonly useDomainRouting: boolean,
    private readonly createdAt: Date,
    private readonly updatedAt: Date,
    private readonly createdBy: string,
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null,
    isActive: boolean,
    profileIds: string[],
    exitOnReject: boolean,
    useDomainRouting: boolean,
    createdAt: Date,
    updatedAt: Date,
    createdBy: string,
  ): IdentityAuthenticationSequence {
    requireText(id, 'authentication sequence id');
    requireText(name, 'authentication sequence name');
    requireText(createdBy, 'authentication sequence createdBy');
    const normalizedProfileIds = normalizeProfileIds(profileIds);
    if (isActive && normalizedProfileIds.length === 0) {
      throw new IdentityConfigIsInvalidException('active authentication sequence requires at least one profile');
    }

    return new IdentityAuthenticationSequence(
      id,
      name,
      normalizeNullable(description),
      isActive,
      normalizedProfileIds,
      exitOnReject,
      useDomainRouting,
      createdAt,
      updatedAt,
      createdBy,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getName(): string {
    return this.name;
  }

  public getDescription(): string | null {
    return this.description;
  }

  public getIsActive(): boolean {
    return this.isActive;
  }

  public getProfileIds(): string[] {
    return [...this.profileIds];
  }

  public getExitOnReject(): boolean {
    return this.exitOnReject;
  }

  public getUseDomainRouting(): boolean {
    return this.useDomainRouting;
  }

  public getCreatedAt(): Date {
    return this.createdAt;
  }

  public getUpdatedAt(): Date {
    return this.updatedAt;
  }

  public getCreatedBy(): string {
    return this.createdBy;
  }
}

function normalizeProfileIds(profileIds: string[]): string[] {
  const normalized: string[] = [];
  for (const raw of profileIds) {
    const profileId = raw.trim();
    requireText(profileId, 'authentication sequence profile id');
    if (normalized.includes(profileId)) {
      throw new IdentityConfigIsInvalidException(`duplicate authentication sequence profile id: ${profileId}`);
    }
    normalized.push(profileId);
  }
  return normalized;
}

function requireText(value: string, field: string): void {
  if (!value.trim()) {
    throw new IdentityConfigIsInvalidException(`${field} is required`);
  }
}

function normalizeNullable(value: string | null): string | null {
  const normalized = value?.trim() ?? '';
  return normalized ? normalized : null;
}
