import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';
import { LdapServerEndpoint } from './ldap-server-endpoint.entity.js';

export type LdapTlsMode = 'disabled' | 'starttls' | 'ldaps';
export type LdapServerType = 'active_directory' | 'e_directory' | 'sun' | 'other';

export interface LdapGroupMapping {
  userBaseDn: string;
  userFilterAttribute: string;
  userNameAttribute: string;
  groupBaseDn: string;
  groupMemberAttribute: string;
  groupNameAttribute: string;
  includeGroups: string[];
  updateIntervalSeconds: number;
}

export interface LdapServerProfileOptions {
  serverType?: LdapServerType;
  baseDn?: string;
  verifyServerCertificate?: boolean;
  certificateProfileRef?: string | null;
  connectTimeoutMs?: number;
  searchTimeoutMs?: number;
  retryIntervalSeconds?: number;
  userNameAttribute?: string;
  includeGroups?: string[];
  updateIntervalSeconds?: number;
}

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
    private serverType: LdapServerType,
    private baseDn: string,
    private verifyServerCertificate: boolean,
    private certificateProfileRef: string | null,
    private connectTimeoutMs: number,
    private searchTimeoutMs: number,
    private retryIntervalSeconds: number,
    private groupMapping: LdapGroupMapping,
    private readonly servers: LdapServerEndpoint[],
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
    servers: LdapServerEndpoint[] | null = null,
    options: LdapServerProfileOptions | null = null,
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
    const serverType = requireServerType(options?.serverType ?? 'active_directory');
    const baseDn = requireNormalizedText(options?.baseDn ?? userBaseDn, 'ldap baseDn');
    const verifyServerCertificate = options?.verifyServerCertificate ?? false;
    const certificateProfileRef = normalizeNullable(options?.certificateProfileRef ?? null);
    if (verifyServerCertificate && !certificateProfileRef) {
      throw new IdentityConfigIsInvalidException('ldap certificateProfileRef is required when server certificate verification is enabled');
    }
    const connectTimeoutMs = requirePositiveValue(options?.connectTimeoutMs ?? timeoutMs, 'ldap connectTimeoutMs');
    const searchTimeoutMs = requirePositiveValue(options?.searchTimeoutMs ?? timeoutMs, 'ldap searchTimeoutMs');
    const retryIntervalSeconds = requirePositiveValue(options?.retryIntervalSeconds ?? 60, 'ldap retryIntervalSeconds');
    const updateIntervalSeconds = requirePositiveValue(options?.updateIntervalSeconds ?? cacheTtlSeconds, 'ldap groupMapping updateIntervalSeconds');
    const groupMapping = {
      userBaseDn,
      userFilterAttribute,
      userNameAttribute: requireNormalizedText(options?.userNameAttribute ?? userFilterAttribute, 'ldap groupMapping userNameAttribute'),
      groupBaseDn,
      groupMemberAttribute,
      groupNameAttribute,
      includeGroups: normalizeIncludeGroups(options?.includeGroups ?? []),
      updateIntervalSeconds,
    };
    const endpointList = servers ?? [
      LdapServerEndpoint.create(
        id,
        name,
        host,
        port,
        1,
        isActive,
      ),
    ];
    assertUnique(endpointList.map((endpoint) => String(endpoint.getPriority())), 'ldap endpoint priority');
    if (isActive && endpointList.every((endpoint) => !endpoint.getIsActive())) {
      throw new IdentityConfigIsInvalidException('active ldap profile requires at least one active endpoint');
    }

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
      serverType,
      baseDn,
      verifyServerCertificate,
      certificateProfileRef,
      connectTimeoutMs,
      searchTimeoutMs,
      retryIntervalSeconds,
      groupMapping,
      [...endpointList],
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

  public getServerType(): LdapServerType {
    return this.serverType;
  }

  public getBaseDn(): string {
    return this.baseDn;
  }

  public getVerifyServerCertificate(): boolean {
    return this.verifyServerCertificate;
  }

  public getCertificateProfileRef(): string | null {
    return this.certificateProfileRef;
  }

  public getConnectTimeoutMs(): number {
    return this.connectTimeoutMs;
  }

  public getSearchTimeoutMs(): number {
    return this.searchTimeoutMs;
  }

  public getRetryIntervalSeconds(): number {
    return this.retryIntervalSeconds;
  }

  public getGroupMapping(): LdapGroupMapping {
    return {
      ...this.groupMapping,
      includeGroups: [...this.groupMapping.includeGroups],
    };
  }

  public getServers(): LdapServerEndpoint[] {
    return [...this.servers];
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

function requirePositiveValue(value: number, field: string): number {
  requirePositive(value, field);
  return value;
}

function requireNormalizedText(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new IdentityConfigIsInvalidException(`${field} is required`);
  }
  return normalized;
}

function normalizeNullable(value: string | null): string | null {
  const normalized = value?.trim() ?? '';
  return normalized ? normalized : null;
}

function requireServerType(value: string): LdapServerType {
  if (!['active_directory', 'e_directory', 'sun', 'other'].includes(value)) {
    throw new IdentityConfigIsInvalidException('ldap serverType is invalid');
  }

  return value as LdapServerType;
}

function normalizeIncludeGroups(values: string[]): string[] {
  const normalized = new Set<string>();

  for (const value of values) {
    const group = value.trim();
    if (!group) {
      throw new IdentityConfigIsInvalidException('ldap groupMapping includeGroups contains an empty group');
    }
    normalized.add(group);
  }

  return [...normalized];
}

function assertUnique(values: string[], field: string): void {
  const seen = new Set<string>();

  for (const value of values) {
    if (seen.has(value)) {
      throw new IdentityConfigIsInvalidException(`duplicate ${field}: ${value}`);
    }
    seen.add(value);
  }
}
