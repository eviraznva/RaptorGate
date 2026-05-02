import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { Role } from '../enums/role.enum.js';

export type IdentityAuthenticationProvider = 'radius' | 'ldap' | 'local';
export type IdentityGroupSource = 'none' | 'ldap' | 'radius_vsa';
export type AdminRoleMappingMatchType = 'username' | 'ldap_group' | 'radius_vsa';
export type AdminRoleMappingRole = 'super_admin' | 'admin' | 'operator' | 'viewer';

export interface AdminRoleMapping {
  matchType: AdminRoleMappingMatchType;
  matchValue: string;
  role: AdminRoleMappingRole;
}

export class IdentityAuthenticationProfile {
  private constructor(
    private readonly id: string,
    private name: string,
    private description: string | null,
    private isActive: boolean,
    private provider: IdentityAuthenticationProvider,
    private radiusProfileId: string | null,
    private ldapProfileId: string | null,
    private groupSource: IdentityGroupSource,
    private sessionTtlSeconds: number,
    private readonly createdAt: Date,
    private updatedAt: Date,
    private readonly createdBy: string,
    private readonly adminRoleMappings: AdminRoleMapping[],
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null,
    isActive: boolean,
    provider: IdentityAuthenticationProvider,
    radiusProfileId: string | null,
    ldapProfileId: string | null,
    groupSource: IdentityGroupSource,
    sessionTtlSeconds: number,
    createdAt: Date,
    updatedAt: Date,
    createdBy: string,
    adminRoleMappings: AdminRoleMapping[] = [],
  ): IdentityAuthenticationProfile {
    requireText(id, 'authentication profile id');
    requireText(name, 'authentication profile name');
    requirePositive(sessionTtlSeconds, 'authentication profile sessionTtlSeconds');

    const normalizedRadiusProfileId = normalizeNullable(radiusProfileId);
    const normalizedLdapProfileId = normalizeNullable(ldapProfileId);

    if (provider === 'radius' && !normalizedRadiusProfileId) {
      throw new IdentityConfigIsInvalidException('radius authentication profile requires radiusProfileId');
    }

    if (provider === 'ldap' && !normalizedLdapProfileId) {
      throw new IdentityConfigIsInvalidException('ldap authentication profile requires ldapProfileId');
    }

    if (provider === 'local' && normalizedRadiusProfileId) {
      throw new IdentityConfigIsInvalidException('local authentication profile cannot reference radiusProfileId');
    }

    if (groupSource === 'ldap' && !normalizedLdapProfileId) {
      throw new IdentityConfigIsInvalidException('ldap group source requires ldapProfileId');
    }

    if (groupSource === 'radius_vsa' && provider !== 'radius') {
      throw new IdentityConfigIsInvalidException('radius_vsa group source requires radius provider');
    }

    return new IdentityAuthenticationProfile(
      id,
      name,
      description,
      isActive,
      provider,
      normalizedRadiusProfileId,
      normalizedLdapProfileId,
      groupSource,
      sessionTtlSeconds,
      createdAt,
      updatedAt,
      createdBy,
      normalizeAdminRoleMappings(adminRoleMappings),
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

  public getProvider(): IdentityAuthenticationProvider {
    return this.provider;
  }

  public getRadiusProfileId(): string | null {
    return this.radiusProfileId;
  }

  public getLdapProfileId(): string | null {
    return this.ldapProfileId;
  }

  public getGroupSource(): IdentityGroupSource {
    return this.groupSource;
  }

  public getSessionTtlSeconds(): number {
    return this.sessionTtlSeconds;
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

  public getAdminRoleMappings(): AdminRoleMapping[] {
    return this.adminRoleMappings.map((mapping) => ({ ...mapping }));
  }
}

function requireText(value: string, field: string): void {
  if (!value.trim()) {
    throw new IdentityConfigIsInvalidException(`${field} is required`);
  }
}

function requirePositive(value: number, field: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new IdentityConfigIsInvalidException(`${field} must be positive`);
  }
}

function normalizeNullable(value: string | null): string | null {
  const normalized = value?.trim() ?? '';
  return normalized ? normalized : null;
}

function normalizeAdminRoleMappings(
  mappings: AdminRoleMapping[],
): AdminRoleMapping[] {
  return mappings.map((mapping) => {
    requireMappingType(mapping.matchType);
    requireText(mapping.matchValue, 'admin role mapping matchValue');
    requireRole(mapping.role);
    return {
      matchType: mapping.matchType,
      matchValue: mapping.matchValue.trim(),
      role: mapping.role,
    };
  });
}

function requireMappingType(matchType: string): void {
  if (!['username', 'ldap_group', 'radius_vsa'].includes(matchType)) {
    throw new IdentityConfigIsInvalidException('admin role mapping matchType is invalid');
  }
}

function requireRole(role: string): void {
  if (![Role.SuperAdmin, Role.Admin, Role.Operator, Role.Viewer].includes(role as Role)) {
    throw new IdentityConfigIsInvalidException('admin role mapping role is invalid');
  }
}
