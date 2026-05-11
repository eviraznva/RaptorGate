import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';

export class RadiusServerProfile {
  private constructor(
    private readonly id: string,
    private name: string,
    private description: string | null,
    private isActive: boolean,
    private host: string,
    private port: number,
    private sharedSecretRef: string,
    private timeoutMs: number,
    private retries: number,
    private nasIp: string | null,
    private nasIdentifier: string | null,
    private calledStationId: string | null,
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
    sharedSecretRef: string,
    timeoutMs: number,
    retries: number,
    nasIp: string | null,
    nasIdentifier: string | null,
    calledStationId: string | null,
    createdAt: Date,
    updatedAt: Date,
    createdBy: string,
  ): RadiusServerProfile {
    requireText(id, 'radius profile id');
    requireText(name, 'radius profile name');
    requireText(host, 'radius host');
    const validatedSharedSecretRef = SecretRef.create(sharedSecretRef);
    requirePort(port, 'radius port');
    requirePositive(timeoutMs, 'radius timeoutMs');
    if (!Number.isInteger(retries) || retries < 0) {
      throw new IdentityConfigIsInvalidException('radius retries must be zero or greater');
    }

    return new RadiusServerProfile(
      id,
      name,
      description,
      isActive,
      host,
      port,
      validatedSharedSecretRef.getValue(),
      timeoutMs,
      retries,
      normalizeNullable(nasIp),
      normalizeNullable(nasIdentifier),
      normalizeNullable(calledStationId),
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

  public getSharedSecretRef(): string {
    return this.sharedSecretRef;
  }

  public getTimeoutMs(): number {
    return this.timeoutMs;
  }

  public getRetries(): number {
    return this.retries;
  }

  public getNasIp(): string | null {
    return this.nasIp;
  }

  public getNasIdentifier(): string | null {
    return this.nasIdentifier;
  }

  public getCalledStationId(): string | null {
    return this.calledStationId;
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

function normalizeNullable(value: string | null): string | null {
  const normalized = value?.trim() ?? '';
  return normalized ? normalized : null;
}
