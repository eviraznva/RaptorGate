import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';

export class LdapServerEndpoint {
  private constructor(
    private readonly id: string,
    private readonly name: string,
    private readonly host: string,
    private readonly port: number,
    private readonly priority: number,
    private readonly isActive: boolean,
  ) {}

  public static create(
    id: string,
    name: string,
    host: string,
    port: number,
    priority: number,
    isActive: boolean,
  ): LdapServerEndpoint {
    requireText(id, 'ldap endpoint id');
    requireText(name, 'ldap endpoint name');
    requireText(host, 'ldap endpoint host');
    requirePort(port, 'ldap endpoint port');
    requirePriority(priority, 'ldap endpoint priority');

    return new LdapServerEndpoint(
      id,
      name,
      host,
      port,
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
