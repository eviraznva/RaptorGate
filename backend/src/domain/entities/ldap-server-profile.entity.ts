import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';

export type LdapTlsMode = 'disabled' | 'starttls' | 'ldaps';

export class LdapServerProfile {
  private constructor(
    private readonly id: string,
    private name: string,
    private description: string | null,
    private isActive: boolean,
    private host: string,
    private port: number,
    private tlsMode: LdapTlsMode,
    private bindDn: string,
    private bindPasswordRef: string,
    private userBaseDn: string,
    private userFilterAttribute: string,
    private groupBaseDn: string,
    private groupMemberAttribute: string,
    private groupNameAttribute: string,
    private timeoutMs: number,
    private cacheTtlSeconds: number,
    private readonly createdAt: Date,
    private updatedAt: Date,
    private readonly createdBy: string,
  ) {}

  public static create(
    id: string,
    name: string,
    description: string | null,
    isActive: boolean,
    host: string,
    port: number,
    tlsMode: LdapTlsMode,
    bindDn: string,
    bindPasswordRef: string,
    userBaseDn: string,
    userFilterAttribute: string,
    groupBaseDn: string,
    groupMemberAttribute: string,
    groupNameAttribute: string,
    timeoutMs: number,
    cacheTtlSeconds: number,
    createdAt: Date,
    updatedAt: Date,
    createdBy: string,
  ): LdapServerProfile {
    requireText(id, 'ldap profile id');
    requireText(name, 'ldap profile name');
    requireText(host, 'ldap host');
    requireText(bindDn, 'ldap bindDn');
    const validatedBindPasswordRef = SecretRef.create(bindPasswordRef);
    requireText(userBaseDn, 'ldap userBaseDn');
    requireText(userFilterAttribute, 'ldap userFilterAttribute');
    requireText(groupBaseDn, 'ldap groupBaseDn');
    requireText(groupMemberAttribute, 'ldap groupMemberAttribute');
    requireText(groupNameAttribute, 'ldap groupNameAttribute');
    requirePort(port, 'ldap port');
    requirePositive(timeoutMs, 'ldap timeoutMs');
    requirePositive(cacheTtlSeconds, 'ldap cacheTtlSeconds');

    return new LdapServerProfile(
      id,
      name,
      description,
      isActive,
      host,
      port,
      tlsMode,
      bindDn,
      validatedBindPasswordRef.getValue(),
      userBaseDn,
      userFilterAttribute,
      groupBaseDn,
      groupMemberAttribute,
      groupNameAttribute,
      timeoutMs,
      cacheTtlSeconds,
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

  public getHost(): string {
    return this.host;
  }

  public getPort(): number {
    return this.port;
  }

  public getTlsMode(): LdapTlsMode {
    return this.tlsMode;
  }

  public getBindDn(): string {
    return this.bindDn;
  }

  public getBindPasswordRef(): string {
    return this.bindPasswordRef;
  }

  public getUserBaseDn(): string {
    return this.userBaseDn;
  }

  public getUserFilterAttribute(): string {
    return this.userFilterAttribute;
  }

  public getGroupBaseDn(): string {
    return this.groupBaseDn;
  }

  public getGroupMemberAttribute(): string {
    return this.groupMemberAttribute;
  }

  public getGroupNameAttribute(): string {
    return this.groupNameAttribute;
  }

  public getTimeoutMs(): number {
    return this.timeoutMs;
  }

  public getCacheTtlSeconds(): number {
    return this.cacheTtlSeconds;
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

function requireText(value: string, field: string): void {
  if (!value.trim()) {
    throw new IdentityConfigIsInvalidException(`${field} is required`);
  }
}

function requirePort(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new IdentityConfigIsInvalidException(`${field} must be between 1 and 65535`);
  }
}

function requirePositive(value: number, field: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new IdentityConfigIsInvalidException(`${field} must be positive`);
  }
}
