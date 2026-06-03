import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';

export type IdentityGroupSource = 'local' | 'ldap' | 'radius_vsa';
export type IdentityGroupMemberPrincipalType = 'username' | 'external_id';

export interface IdentityGroupMember {
  principal: string;
  principalType: IdentityGroupMemberPrincipalType;
}

export class IdentityGroup {
  private constructor(
    private readonly id: string,
    private readonly name: string,
    private readonly description: string | null,
    private readonly source: IdentityGroupSource,
    private readonly externalDn: string | null,
    private readonly members: IdentityGroupMember[],
    private readonly createdAt: Date,
    private readonly updatedAt: Date,
    private readonly createdBy: string,
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null,
    source: IdentityGroupSource,
    externalDn: string | null,
    members: IdentityGroupMember[],
    createdAt: Date,
    updatedAt: Date,
    createdBy: string,
  ): IdentityGroup {
    requireText(id, 'identity group id');
    requireText(name, 'identity group name');
    requireSource(source);
    requireText(createdBy, 'identity group createdBy');

    return new IdentityGroup(
      id,
      name.trim(),
      normalizeNullable(description),
      source,
      normalizeNullable(externalDn),
      normalizeMembers(members),
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

  public getSource(): IdentityGroupSource {
    return this.source;
  }

  public getExternalDn(): string | null {
    return this.externalDn;
  }

  public getMembers(): IdentityGroupMember[] {
    return this.members.map((member) => ({ ...member }));
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

function normalizeMembers(members: IdentityGroupMember[]): IdentityGroupMember[] {
  const normalized: IdentityGroupMember[] = [];
  for (const member of members) {
    requireText(member.principal, 'identity group member principal');
    requireMemberType(member.principalType);
    const principal = member.principal.trim();
    if (
      normalized.some(
        (existing) =>
          existing.principal === principal &&
          existing.principalType === member.principalType,
      )
    ) {
      continue;
    }
    normalized.push({ principal, principalType: member.principalType });
  }
  return normalized;
}

function requireText(value: string, field: string): void {
  if (!value.trim()) {
    throw new IdentityConfigIsInvalidException(`${field} is required`);
  }
}

function requireSource(source: string): void {
  if (!['local', 'ldap', 'radius_vsa'].includes(source)) {
    throw new IdentityConfigIsInvalidException('identity group source is invalid');
  }
}

function requireMemberType(type: string): void {
  if (!['username', 'external_id'].includes(type)) {
    throw new IdentityConfigIsInvalidException('identity group member principalType is invalid');
  }
}

function normalizeNullable(value: string | null): string | null {
  const normalized = value?.trim() ?? '';
  return normalized ? normalized : null;
}
