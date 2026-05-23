import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';

export class RadiusServerEndpoint {
  private constructor(
    private readonly id: string,
    private readonly name: string,
    private readonly host: string,
    private readonly port: number,
    private readonly sharedSecretRef: string,
    private readonly priority: number,
    private readonly isActive: boolean,
  ) {}

  public static create(
    id: string,
    name: string,
    host: string,
    port: number,
    sharedSecretRef: string,
    priority: number,
    isActive: boolean,
  ): RadiusServerEndpoint {
    requireText(id, 'radius endpoint id');
    requireText(name, 'radius endpoint name');
    requireText(host, 'radius endpoint host');
    const validatedSharedSecretRef = SecretRef.create(sharedSecretRef);
    requirePort(port, 'radius endpoint port');
    requirePriority(priority, 'radius endpoint priority');

    return new RadiusServerEndpoint(
      id,
      name,
      host,
      port,
      validatedSharedSecretRef.getValue(),
      priority,
      isActive,
    );
  }

  public getId(): string {
    return this.id;
  }

  public getName(): string {
    return this.name;
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

  public getPriority(): number {
    return this.priority;
  }

  public getIsActive(): boolean {
    return this.isActive;
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

function requirePriority(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new IdentityConfigIsInvalidException(`${field} must be between 1 and 65535`);
  }
}
