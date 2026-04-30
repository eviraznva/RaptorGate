# Issue A — First-Class Identity Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move RADIUS/LDAP from process env into the firewall's first-class configuration model (named server profiles + authentication profiles + identity settings), so that captive portal, admin login, and future VPN-style flows all consume the same config snapshot — and so that import/export/apply/rollback round-trip identity config like every other firewall section.

**Architecture:** Mirror the existing per-subdomain pattern (NAT, IPS, DNS, Zones): each new aggregate gets a domain entity, value objects, repository interface, JSON repository implementation, JSON schema, and JSON mapper. New aggregates are added to `ConfigBundlePayload` and mapped in `config-payload.mapper.ts`. Snapshot apply/import/rollback consume new repos. Proto `config_models.proto` and `config_snapshot_service.proto` get parallel messages so the firewall can read identity config from the snapshot. Secrets are stored as opaque references (`SecretRef` VO) only — concrete secret storage lands in Issue B; this plan reserves the contract. A one-shot env-bootstrap seeds the first RADIUS/LDAP profile if the JSON store is empty, so existing deployments do not break, but env stops being the source of truth.

**Tech Stack:** TypeScript / NestJS / Zod / Jest / protobuf3 / @nestjs/microservices gRPC.

**Scope boundaries (explicit):**
- IN scope: domain model, persistence, snapshot wiring (apply/import/export/rollback), proto for snapshot transport, env bootstrap seed, referential integrity (cannot delete profile bound to active auth profile or active identity setting).
- OUT of scope: HTTP CRUD endpoints (Issue C), shared authentication engine refactor (Issue D), admin role mapping (Issue E), frontend (Issue F), runtime session lifecycle (Issue G), removing lab topology assumptions (Issue H), policy cleanup (Issue I), diagnostics/audit (Issue J).
- Issue B (secret storage decision): we introduce the `SecretRef` value object now, but actual secret persistence is added in Issue B. For this plan, `SecretRef` carries an opaque string identifier; the bootstrap seeder writes a placeholder ref. **DO NOT** put plaintext secrets in `ConfigBundlePayload` or in the JSON files written by this plan.

---

## File Structure

### New backend files
- `backend/src/domain/value-objects/secret-ref.vo.ts`
- `backend/src/domain/value-objects/auth-protocol.vo.ts`
- `backend/src/domain/value-objects/ldap-tls-mode.vo.ts`
- `backend/src/domain/value-objects/auth-provider-type.vo.ts`
- `backend/src/domain/value-objects/identity-role-source.vo.ts`
- `backend/src/domain/exceptions/secret-ref-is-invalid.exception.ts`
- `backend/src/domain/exceptions/auth-protocol-is-invalid.exception.ts`
- `backend/src/domain/exceptions/ldap-tls-mode-is-invalid.exception.ts`
- `backend/src/domain/exceptions/auth-provider-type-is-invalid.exception.ts`
- `backend/src/domain/exceptions/identity-role-source-is-invalid.exception.ts`
- `backend/src/domain/exceptions/identity-profile-in-use.exception.ts`
- `backend/src/domain/entities/radius-server-profile.entity.ts`
- `backend/src/domain/entities/ldap-server-profile.entity.ts`
- `backend/src/domain/entities/authentication-profile.entity.ts`
- `backend/src/domain/entities/identity-settings.entity.ts`
- `backend/src/domain/repositories/radius-server-profile.repository.ts`
- `backend/src/domain/repositories/ldap-server-profile.repository.ts`
- `backend/src/domain/repositories/authentication-profile.repository.ts`
- `backend/src/domain/repositories/identity-settings.repository.ts`
- `backend/src/infrastructure/persistence/schemas/radius-server-profiles.schema.ts`
- `backend/src/infrastructure/persistence/schemas/ldap-server-profiles.schema.ts`
- `backend/src/infrastructure/persistence/schemas/authentication-profiles.schema.ts`
- `backend/src/infrastructure/persistence/schemas/identity-settings.schema.ts`
- `backend/src/infrastructure/persistence/mappers/radius-server-profile-json.mapper.ts`
- `backend/src/infrastructure/persistence/mappers/ldap-server-profile-json.mapper.ts`
- `backend/src/infrastructure/persistence/mappers/authentication-profile-json.mapper.ts`
- `backend/src/infrastructure/persistence/mappers/identity-settings-json.mapper.ts`
- `backend/src/infrastructure/persistence/repositories/json-radius-server-profile.repository.ts`
- `backend/src/infrastructure/persistence/repositories/json-ldap-server-profile.repository.ts`
- `backend/src/infrastructure/persistence/repositories/json-authentication-profile.repository.ts`
- `backend/src/infrastructure/persistence/repositories/json-identity-settings.repository.ts`
- `backend/src/application/services/identity-bootstrap-seed.service.ts`
- `backend/src/application/services/identity-referential-integrity.service.ts`
- Per-file `*.spec.ts` unit tests for each VO, mapper, integrity service, bootstrap seed.

### Modified backend files
- `backend/src/domain/value-objects/config-snapshot-payload.interface.ts` — add `radius_server_profiles`, `ldap_server_profiles`, `authentication_profiles`, `identity_settings` sections.
- `backend/src/infrastructure/persistence/mappers/config-payload.mapper.ts` — extend `ConfigBundlePayloadSchema` and both mapping functions.
- `backend/src/application/use-cases/apply-config-snapshot.use-case.ts` — read new repos, include in payload, log counts.
- `backend/src/application/use-cases/import-config.use-case.ts` — parse and `overwriteAll` for new sections, fail closed on missing secret refs.
- `backend/src/application/use-cases/rollback-config.use-case.ts` — `overwriteAll` for new sections.
- (Export-config use case is unchanged: it returns the snapshot as-is. No change required.)
- `backend/src/infrastructure/adapters/grpc-config-snapshot-push.service.ts` — extend `toBundle` to include new sections in the proto payload.
- Wherever NestJS DI providers are registered for the existing JSON repos (locate by `grep -rn "JsonNatRuleRepository" backend/src/`) — register the four new JSON repos.

### Modified proto files
- `proto/config/config_models.proto` — add `SecretRef`, `RadiusServerProfile`, `LdapServerProfile`, `AuthenticationProfile`, `IdentitySettings`, `IdentityConfig` messages and supporting enums.
- `proto/services/config_snapshot_service.proto` — add `IdentityConfig identity_config = 13;` to `ConfigBundle`.

### Data files
- `backend/data/json-db/radius_server_profiles.json` — created on first read with `{ "items": [] }` by file-store default.
- `backend/data/json-db/ldap_server_profiles.json`
- `backend/data/json-db/authentication_profiles.json`
- `backend/data/json-db/identity_settings.json` — singleton `{ "portalAuthProfileId": null, "adminAuthProfileId": null }`.

---

## Conventions to follow (from existing codebase)

- VO: `private constructor`, `static create(value): VO` validates and throws domain exception, getter `getValue` (a getter, not method, in some VOs — check `port.vo.ts`: `public get getValue(): number` — we follow the existing inconsistency where it appears).
- Entity: `private constructor`, `public static create(...)` returns entity, getters `getX()`, setters `setX(...)` only for mutable fields.
- Repo interface: methods + `Symbol('X_REPOSITORY_TOKEN')` exported alongside.
- JSON mapper: static `toDomain(record): Entity` and `toRecord(entity, createdBy?): Record`.
- JSON repo: `@Injectable()`, file path under `data/json-db/<name>.json`, `Mutex.runExclusive` for writes, Zod parse on read with `readJsonOrDefault`.
- Use the explicit `.js` import suffix on local imports (existing pattern, NodeNext ESM).
- Tests: Jest, `*.spec.ts`, AAA structure.
- Comments in Polish, short, never inline inside structs/objects (per repo convention — see existing files).

---

## Domain model (conceptual reference for all tasks)

### `SecretRef`
- Opaque string with prefix `secret://`. Format: `secret://<scope>/<owner-id>/<field>`.
- Examples: `secret://radius-profiles/9b3f.../shared-secret`, `secret://ldap-profiles/abc.../bind-password`.
- Validation: matches `/^secret:\/\/[a-z0-9-]+\/[a-z0-9-]+\/[a-z0-9-]+$/i` (allow uuids and hyphens).
- Carries no plaintext. Issue B will add the resolver. For Issue A, the bootstrap seeder writes a deterministic ref string; runtime callers in later issues will look up the actual value.

### `RadiusServerProfile`
- `id: string` (uuid v4)
- `name: string` (1..64, unique among RadiusServerProfiles)
- `host: string` (FQDN or IP, 1..253)
- `port: Port` (default 1812)
- `timeoutMs: number` (positive int, 1..60000)
- `retries: number` (0..5)
- `nasIp: IpAddress | null`
- `nasIdentifier: string` (1..64)
- `authProtocol: AuthProtocol` (PAP for now; CHAP/MS-CHAPv2 reserved enum values, parse-only — `create` rejects non-PAP with a not-supported message until Issue D adds them)
- `sharedSecretRef: SecretRef`
- `createdAt: Date`, `updatedAt: Date`

### `LdapServerProfile`
- `id: string`, `name: string` (unique)
- `host: string`, `port: Port` (default 389/636 by tlsMode)
- `tlsMode: LdapTlsMode` (`none` | `starttls` | `ldaps`)
- `bindDn: string` (1..512)
- `bindPasswordRef: SecretRef`
- `userBaseDn: string`, `userFilterAttribute: string` (e.g. `uid`)
- `groupBaseDn: string`, `groupMemberAttribute: string`, `groupNameAttribute: string`
- `timeoutMs: number` (1..60000)
- `createdAt: Date`, `updatedAt: Date`

### `AuthenticationProfile`
- `id: string`, `name: string` (unique)
- `providerType: AuthProviderType` (`radius` | `ldap` | `local`)
- `serverProfileId: string | null` (must be set when type is radius or ldap; must be null when local)
- `allowList: string[]` (group names allowed to authenticate; empty array = allow all authenticated users)
- `groupSource: IdentityRoleSource` (`ldap` | `radius_vsa` | `local_table`) — Issue E uses this; Issue A persists it.
- `roleMappingMode: 'strict' | 'permissive'` — strict = no role → reject; permissive = no role → default reader. Issue E enforces; Issue A persists.
- `createdAt: Date`, `updatedAt: Date`

### `IdentitySettings` (singleton)
- `portalAuthProfileId: string | null` — captive portal auth profile.
- `adminAuthProfileId: string | null` — firewall admin login.
- `vpnAuthProfileId: string | null` — reserved for future VPN-like flows.
- Stored as a single object (not a list) in `identity_settings.json`.

### Referential integrity
- Cannot delete a `RadiusServerProfile` referenced by any `AuthenticationProfile`.
- Cannot delete an `LdapServerProfile` referenced by any `AuthenticationProfile`.
- Cannot delete an `AuthenticationProfile` referenced by `IdentitySettings`.
- All four checks live in `IdentityReferentialIntegrityService`.
- `IdentityProfileInUseException` carries the offending references for diagnostics.

---

## Section 1 — Value Objects

### Task 1.1: `SecretRef` value object

**Files:**
- Create: `backend/src/domain/exceptions/secret-ref-is-invalid.exception.ts`
- Create: `backend/src/domain/value-objects/secret-ref.vo.ts`
- Test:   `backend/src/domain/value-objects/secret-ref.vo.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// backend/src/domain/value-objects/secret-ref.vo.spec.ts
import { SecretRef } from './secret-ref.vo.js';
import { SecretRefIsInvalidException } from '../exceptions/secret-ref-is-invalid.exception.js';

describe('SecretRef', () => {
  it('accepts well-formed secret reference', () => {
    const ref = SecretRef.create('secret://radius-profiles/9b3fa08c/shared-secret');
    expect(ref.getValue).toBe('secret://radius-profiles/9b3fa08c/shared-secret');
  });

  it('rejects empty string', () => {
    expect(() => SecretRef.create('')).toThrow(SecretRefIsInvalidException);
  });

  it('rejects plaintext shaped value', () => {
    expect(() => SecretRef.create('hunter2')).toThrow(SecretRefIsInvalidException);
  });

  it('rejects wrong scheme', () => {
    expect(() => SecretRef.create('http://example.com/secret')).toThrow(SecretRefIsInvalidException);
  });

  it('rejects extra path segments', () => {
    expect(() => SecretRef.create('secret://a/b/c/d')).toThrow(SecretRefIsInvalidException);
  });

  it('exposes scope, owner, field components', () => {
    const ref = SecretRef.create('secret://radius-profiles/9b3fa08c/shared-secret');
    expect(ref.getScope()).toBe('radius-profiles');
    expect(ref.getOwnerId()).toBe('9b3fa08c');
    expect(ref.getField()).toBe('shared-secret');
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- secret-ref.vo.spec`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement the exception**

```typescript
// backend/src/domain/exceptions/secret-ref-is-invalid.exception.ts
export class SecretRefIsInvalidException extends Error {
  constructor(value: string) {
    super(`Invalid secret reference: ${value}`);
    this.name = 'SecretRefIsInvalidException';
  }
}
```

- [ ] **Step 4: Implement the value object**

```typescript
// backend/src/domain/value-objects/secret-ref.vo.ts
import { SecretRefIsInvalidException } from '../exceptions/secret-ref-is-invalid.exception.js';

const SECRET_REF_PATTERN = /^secret:\/\/([a-z0-9-]+)\/([a-z0-9-]+)\/([a-z0-9-]+)$/i;

export class SecretRef {
  private readonly value: string;
  private readonly scope: string;
  private readonly ownerId: string;
  private readonly field: string;

  private constructor(value: string, scope: string, ownerId: string, field: string) {
    this.value = value;
    this.scope = scope;
    this.ownerId = ownerId;
    this.field = field;
  }

  public static create(value: string): SecretRef {
    const match = SECRET_REF_PATTERN.exec(value);
    if (!match) throw new SecretRefIsInvalidException(value);
    const [, scope, ownerId, field] = match;
    return new SecretRef(value, scope, ownerId, field);
  }

  public get getValue(): string { return this.value; }
  public getScope(): string { return this.scope; }
  public getOwnerId(): string { return this.ownerId; }
  public getField(): string { return this.field; }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd backend && npm test -- secret-ref.vo.spec`
Expected: PASS, 6 assertions.

- [ ] **Step 6: Commit**

```bash
git add backend/src/domain/value-objects/secret-ref.vo.ts \
        backend/src/domain/value-objects/secret-ref.vo.spec.ts \
        backend/src/domain/exceptions/secret-ref-is-invalid.exception.ts
git commit -m "feat(identity): add SecretRef value object"
```

---

### Task 1.2: `AuthProtocol` value object

**Files:**
- Create: `backend/src/domain/exceptions/auth-protocol-is-invalid.exception.ts`
- Create: `backend/src/domain/value-objects/auth-protocol.vo.ts`
- Test:   `backend/src/domain/value-objects/auth-protocol.vo.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import { AuthProtocol, AuthProtocolValue } from './auth-protocol.vo.js';
import { AuthProtocolIsInvalidException } from '../exceptions/auth-protocol-is-invalid.exception.js';

describe('AuthProtocol', () => {
  it('accepts pap', () => {
    expect(AuthProtocol.create('pap').getValue).toBe('pap');
  });

  it('rejects unknown value', () => {
    expect(() => AuthProtocol.create('mschapv3' as AuthProtocolValue)).toThrow(AuthProtocolIsInvalidException);
  });

  it('parses but flags chap as not-implemented in flag method', () => {
    const proto = AuthProtocol.create('chap');
    expect(proto.getValue).toBe('chap');
    expect(proto.isImplemented()).toBe(false);
  });

  it('flags pap as implemented', () => {
    expect(AuthProtocol.create('pap').isImplemented()).toBe(true);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- auth-protocol.vo.spec`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement exception**

```typescript
// backend/src/domain/exceptions/auth-protocol-is-invalid.exception.ts
export class AuthProtocolIsInvalidException extends Error {
  constructor(value: string) {
    super(`Invalid auth protocol: ${value}`);
    this.name = 'AuthProtocolIsInvalidException';
  }
}
```

- [ ] **Step 4: Implement VO**

```typescript
// backend/src/domain/value-objects/auth-protocol.vo.ts
import { AuthProtocolIsInvalidException } from '../exceptions/auth-protocol-is-invalid.exception.js';

export type AuthProtocolValue = 'pap' | 'chap' | 'mschapv2';

const ALLOWED: ReadonlySet<AuthProtocolValue> = new Set(['pap', 'chap', 'mschapv2']);
const IMPLEMENTED: ReadonlySet<AuthProtocolValue> = new Set(['pap']);

export class AuthProtocol {
  private readonly value: AuthProtocolValue;

  private constructor(value: AuthProtocolValue) { this.value = value; }

  public static create(value: string): AuthProtocol {
    if (!ALLOWED.has(value as AuthProtocolValue)) {
      throw new AuthProtocolIsInvalidException(value);
    }
    return new AuthProtocol(value as AuthProtocolValue);
  }

  public get getValue(): AuthProtocolValue { return this.value; }
  public isImplemented(): boolean { return IMPLEMENTED.has(this.value); }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd backend && npm test -- auth-protocol.vo.spec`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/domain/value-objects/auth-protocol.vo.ts \
        backend/src/domain/value-objects/auth-protocol.vo.spec.ts \
        backend/src/domain/exceptions/auth-protocol-is-invalid.exception.ts
git commit -m "feat(identity): add AuthProtocol value object"
```

---

### Task 1.3: `LdapTlsMode` value object

**Files:**
- Create: `backend/src/domain/exceptions/ldap-tls-mode-is-invalid.exception.ts`
- Create: `backend/src/domain/value-objects/ldap-tls-mode.vo.ts`
- Test:   `backend/src/domain/value-objects/ldap-tls-mode.vo.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import { LdapTlsMode } from './ldap-tls-mode.vo.js';
import { LdapTlsModeIsInvalidException } from '../exceptions/ldap-tls-mode-is-invalid.exception.js';

describe('LdapTlsMode', () => {
  it.each(['none', 'starttls', 'ldaps'] as const)('accepts %s', (m) => {
    expect(LdapTlsMode.create(m).getValue).toBe(m);
  });

  it('rejects unknown', () => {
    expect(() => LdapTlsMode.create('plain')).toThrow(LdapTlsModeIsInvalidException);
  });

  it('reports default port for ldaps as 636', () => {
    expect(LdapTlsMode.create('ldaps').getDefaultPort()).toBe(636);
  });

  it('reports default port for none/starttls as 389', () => {
    expect(LdapTlsMode.create('none').getDefaultPort()).toBe(389);
    expect(LdapTlsMode.create('starttls').getDefaultPort()).toBe(389);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- ldap-tls-mode.vo.spec`
Expected: FAIL.

- [ ] **Step 3: Implement exception + VO**

```typescript
// backend/src/domain/exceptions/ldap-tls-mode-is-invalid.exception.ts
export class LdapTlsModeIsInvalidException extends Error {
  constructor(value: string) {
    super(`Invalid LDAP TLS mode: ${value}`);
    this.name = 'LdapTlsModeIsInvalidException';
  }
}
```

```typescript
// backend/src/domain/value-objects/ldap-tls-mode.vo.ts
import { LdapTlsModeIsInvalidException } from '../exceptions/ldap-tls-mode-is-invalid.exception.js';

export type LdapTlsModeValue = 'none' | 'starttls' | 'ldaps';

const ALLOWED: ReadonlySet<LdapTlsModeValue> = new Set(['none', 'starttls', 'ldaps']);

export class LdapTlsMode {
  private readonly value: LdapTlsModeValue;
  private constructor(value: LdapTlsModeValue) { this.value = value; }

  public static create(value: string): LdapTlsMode {
    if (!ALLOWED.has(value as LdapTlsModeValue)) {
      throw new LdapTlsModeIsInvalidException(value);
    }
    return new LdapTlsMode(value as LdapTlsModeValue);
  }

  public get getValue(): LdapTlsModeValue { return this.value; }
  public getDefaultPort(): number { return this.value === 'ldaps' ? 636 : 389; }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && npm test -- ldap-tls-mode.vo.spec`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/domain/value-objects/ldap-tls-mode.vo.ts \
        backend/src/domain/value-objects/ldap-tls-mode.vo.spec.ts \
        backend/src/domain/exceptions/ldap-tls-mode-is-invalid.exception.ts
git commit -m "feat(identity): add LdapTlsMode value object"
```

---

### Task 1.4: `AuthProviderType` value object

**Files:**
- Create: `backend/src/domain/exceptions/auth-provider-type-is-invalid.exception.ts`
- Create: `backend/src/domain/value-objects/auth-provider-type.vo.ts`
- Test:   `backend/src/domain/value-objects/auth-provider-type.vo.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import { AuthProviderType } from './auth-provider-type.vo.js';
import { AuthProviderTypeIsInvalidException } from '../exceptions/auth-provider-type-is-invalid.exception.js';

describe('AuthProviderType', () => {
  it.each(['radius', 'ldap', 'local'] as const)('accepts %s', (v) => {
    expect(AuthProviderType.create(v).getValue).toBe(v);
  });
  it('rejects unknown', () => {
    expect(() => AuthProviderType.create('saml')).toThrow(AuthProviderTypeIsInvalidException);
  });
  it('requires server profile for radius/ldap', () => {
    expect(AuthProviderType.create('radius').requiresServerProfile()).toBe(true);
    expect(AuthProviderType.create('ldap').requiresServerProfile()).toBe(true);
    expect(AuthProviderType.create('local').requiresServerProfile()).toBe(false);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- auth-provider-type.vo.spec`
Expected: FAIL.

- [ ] **Step 3: Implement exception + VO**

```typescript
// backend/src/domain/exceptions/auth-provider-type-is-invalid.exception.ts
export class AuthProviderTypeIsInvalidException extends Error {
  constructor(value: string) {
    super(`Invalid auth provider type: ${value}`);
    this.name = 'AuthProviderTypeIsInvalidException';
  }
}
```

```typescript
// backend/src/domain/value-objects/auth-provider-type.vo.ts
import { AuthProviderTypeIsInvalidException } from '../exceptions/auth-provider-type-is-invalid.exception.js';

export type AuthProviderTypeValue = 'radius' | 'ldap' | 'local';

const ALLOWED: ReadonlySet<AuthProviderTypeValue> = new Set(['radius', 'ldap', 'local']);

export class AuthProviderType {
  private readonly value: AuthProviderTypeValue;
  private constructor(value: AuthProviderTypeValue) { this.value = value; }

  public static create(value: string): AuthProviderType {
    if (!ALLOWED.has(value as AuthProviderTypeValue)) {
      throw new AuthProviderTypeIsInvalidException(value);
    }
    return new AuthProviderType(value as AuthProviderTypeValue);
  }

  public get getValue(): AuthProviderTypeValue { return this.value; }
  public requiresServerProfile(): boolean {
    return this.value === 'radius' || this.value === 'ldap';
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && npm test -- auth-provider-type.vo.spec`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/domain/value-objects/auth-provider-type.vo.ts \
        backend/src/domain/value-objects/auth-provider-type.vo.spec.ts \
        backend/src/domain/exceptions/auth-provider-type-is-invalid.exception.ts
git commit -m "feat(identity): add AuthProviderType value object"
```

---

### Task 1.5: `IdentityRoleSource` value object

**Files:**
- Create: `backend/src/domain/exceptions/identity-role-source-is-invalid.exception.ts`
- Create: `backend/src/domain/value-objects/identity-role-source.vo.ts`
- Test:   `backend/src/domain/value-objects/identity-role-source.vo.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import { IdentityRoleSource } from './identity-role-source.vo.js';
import { IdentityRoleSourceIsInvalidException } from '../exceptions/identity-role-source-is-invalid.exception.js';

describe('IdentityRoleSource', () => {
  it.each(['ldap', 'radius_vsa', 'local_table'] as const)('accepts %s', (v) => {
    expect(IdentityRoleSource.create(v).getValue).toBe(v);
  });
  it('rejects unknown', () => {
    expect(() => IdentityRoleSource.create('oidc')).toThrow(IdentityRoleSourceIsInvalidException);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- identity-role-source.vo.spec`
Expected: FAIL.

- [ ] **Step 3: Implement exception + VO**

```typescript
// backend/src/domain/exceptions/identity-role-source-is-invalid.exception.ts
export class IdentityRoleSourceIsInvalidException extends Error {
  constructor(value: string) {
    super(`Invalid identity role source: ${value}`);
    this.name = 'IdentityRoleSourceIsInvalidException';
  }
}
```

```typescript
// backend/src/domain/value-objects/identity-role-source.vo.ts
import { IdentityRoleSourceIsInvalidException } from '../exceptions/identity-role-source-is-invalid.exception.js';

export type IdentityRoleSourceValue = 'ldap' | 'radius_vsa' | 'local_table';

const ALLOWED: ReadonlySet<IdentityRoleSourceValue> = new Set([
  'ldap',
  'radius_vsa',
  'local_table',
]);

export class IdentityRoleSource {
  private readonly value: IdentityRoleSourceValue;
  private constructor(value: IdentityRoleSourceValue) { this.value = value; }

  public static create(value: string): IdentityRoleSource {
    if (!ALLOWED.has(value as IdentityRoleSourceValue)) {
      throw new IdentityRoleSourceIsInvalidException(value);
    }
    return new IdentityRoleSource(value as IdentityRoleSourceValue);
  }

  public get getValue(): IdentityRoleSourceValue { return this.value; }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && npm test -- identity-role-source.vo.spec`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/domain/value-objects/identity-role-source.vo.ts \
        backend/src/domain/value-objects/identity-role-source.vo.spec.ts \
        backend/src/domain/exceptions/identity-role-source-is-invalid.exception.ts
git commit -m "feat(identity): add IdentityRoleSource value object"
```

---

## Section 2 — Entities

### Task 2.1: `RadiusServerProfile` entity

**Files:**
- Create: `backend/src/domain/entities/radius-server-profile.entity.ts`
- Test:   `backend/src/domain/entities/radius-server-profile.entity.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import { RadiusServerProfile } from './radius-server-profile.entity.js';
import { AuthProtocol } from '../value-objects/auth-protocol.vo.js';
import { IpAddress } from '../value-objects/ip-address.vo.js';
import { Port } from '../value-objects/port.vo.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';

describe('RadiusServerProfile', () => {
  const baseArgs = () => ({
    id: '11111111-1111-1111-1111-111111111111',
    name: 'lab-radius',
    host: '192.168.20.30',
    port: Port.create(1812),
    timeoutMs: 3000,
    retries: 1,
    nasIp: IpAddress.create('192.168.20.254'),
    nasIdentifier: 'raptorgate-backend',
    authProtocol: AuthProtocol.create('pap'),
    sharedSecretRef: SecretRef.create('secret://radius-profiles/11111111/shared-secret'),
    createdAt: new Date('2026-04-30T00:00:00Z'),
    updatedAt: new Date('2026-04-30T00:00:00Z'),
  });

  it('constructs with create() and exposes all getters', () => {
    const args = baseArgs();
    const p = RadiusServerProfile.create(
      args.id, args.name, args.host, args.port, args.timeoutMs, args.retries,
      args.nasIp, args.nasIdentifier, args.authProtocol, args.sharedSecretRef,
      args.createdAt, args.updatedAt,
    );
    expect(p.getId()).toBe(args.id);
    expect(p.getName()).toBe(args.name);
    expect(p.getHost()).toBe(args.host);
    expect(p.getPort()).toBe(args.port);
    expect(p.getTimeoutMs()).toBe(3000);
    expect(p.getRetries()).toBe(1);
    expect(p.getNasIp()).toBe(args.nasIp);
    expect(p.getNasIdentifier()).toBe('raptorgate-backend');
    expect(p.getAuthProtocol()).toBe(args.authProtocol);
    expect(p.getSharedSecretRef()).toBe(args.sharedSecretRef);
  });

  it('rejects timeoutMs <= 0', () => {
    const args = baseArgs();
    expect(() => RadiusServerProfile.create(
      args.id, args.name, args.host, args.port, 0, args.retries,
      args.nasIp, args.nasIdentifier, args.authProtocol, args.sharedSecretRef,
      args.createdAt, args.updatedAt,
    )).toThrow(/timeout/i);
  });

  it('rejects retries > 5', () => {
    const args = baseArgs();
    expect(() => RadiusServerProfile.create(
      args.id, args.name, args.host, args.port, args.timeoutMs, 6,
      args.nasIp, args.nasIdentifier, args.authProtocol, args.sharedSecretRef,
      args.createdAt, args.updatedAt,
    )).toThrow(/retries/i);
  });

  it('rejects empty name', () => {
    const args = baseArgs();
    expect(() => RadiusServerProfile.create(
      args.id, '', args.host, args.port, args.timeoutMs, args.retries,
      args.nasIp, args.nasIdentifier, args.authProtocol, args.sharedSecretRef,
      args.createdAt, args.updatedAt,
    )).toThrow(/name/i);
  });

  it('rejects empty host', () => {
    const args = baseArgs();
    expect(() => RadiusServerProfile.create(
      args.id, args.name, '', args.port, args.timeoutMs, args.retries,
      args.nasIp, args.nasIdentifier, args.authProtocol, args.sharedSecretRef,
      args.createdAt, args.updatedAt,
    )).toThrow(/host/i);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- radius-server-profile.entity.spec`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement entity**

```typescript
// backend/src/domain/entities/radius-server-profile.entity.ts
import { AuthProtocol } from '../value-objects/auth-protocol.vo.js';
import { IpAddress } from '../value-objects/ip-address.vo.js';
import { Port } from '../value-objects/port.vo.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';

export class RadiusServerProfile {
  private constructor(
    private readonly id: string,
    private name: string,
    private host: string,
    private port: Port,
    private timeoutMs: number,
    private retries: number,
    private nasIp: IpAddress | null,
    private nasIdentifier: string,
    private authProtocol: AuthProtocol,
    private sharedSecretRef: SecretRef,
    private readonly createdAt: Date,
    private updatedAt: Date,
  ) {}

  public static create(
    id: string,
    name: string,
    host: string,
    port: Port,
    timeoutMs: number,
    retries: number,
    nasIp: IpAddress | null,
    nasIdentifier: string,
    authProtocol: AuthProtocol,
    sharedSecretRef: SecretRef,
    createdAt: Date,
    updatedAt: Date,
  ): RadiusServerProfile {
    if (!name || name.length === 0 || name.length > 64) {
      throw new Error('RadiusServerProfile name must be 1..64 chars');
    }
    if (!host || host.length === 0 || host.length > 253) {
      throw new Error('RadiusServerProfile host must be 1..253 chars');
    }
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) {
      throw new Error('RadiusServerProfile timeoutMs must be 1..60000');
    }
    if (!Number.isInteger(retries) || retries < 0 || retries > 5) {
      throw new Error('RadiusServerProfile retries must be 0..5');
    }
    if (!nasIdentifier || nasIdentifier.length === 0 || nasIdentifier.length > 64) {
      throw new Error('RadiusServerProfile nasIdentifier must be 1..64 chars');
    }
    return new RadiusServerProfile(
      id, name, host, port, timeoutMs, retries,
      nasIp, nasIdentifier, authProtocol, sharedSecretRef,
      createdAt, updatedAt,
    );
  }

  public getId(): string { return this.id; }
  public getName(): string { return this.name; }
  public getHost(): string { return this.host; }
  public getPort(): Port { return this.port; }
  public getTimeoutMs(): number { return this.timeoutMs; }
  public getRetries(): number { return this.retries; }
  public getNasIp(): IpAddress | null { return this.nasIp; }
  public getNasIdentifier(): string { return this.nasIdentifier; }
  public getAuthProtocol(): AuthProtocol { return this.authProtocol; }
  public getSharedSecretRef(): SecretRef { return this.sharedSecretRef; }
  public getCreatedAt(): Date { return this.createdAt; }
  public getUpdatedAt(): Date { return this.updatedAt; }

  public setName(name: string): void {
    if (!name || name.length === 0 || name.length > 64) throw new Error('invalid name');
    this.name = name;
  }
  public setHost(host: string): void {
    if (!host || host.length === 0 || host.length > 253) throw new Error('invalid host');
    this.host = host;
  }
  public setPort(port: Port): void { this.port = port; }
  public setTimeoutMs(ms: number): void {
    if (!Number.isInteger(ms) || ms <= 0 || ms > 60000) throw new Error('invalid timeoutMs');
    this.timeoutMs = ms;
  }
  public setRetries(r: number): void {
    if (!Number.isInteger(r) || r < 0 || r > 5) throw new Error('invalid retries');
    this.retries = r;
  }
  public setNasIp(ip: IpAddress | null): void { this.nasIp = ip; }
  public setNasIdentifier(id: string): void {
    if (!id || id.length === 0 || id.length > 64) throw new Error('invalid nasIdentifier');
    this.nasIdentifier = id;
  }
  public setAuthProtocol(p: AuthProtocol): void { this.authProtocol = p; }
  public setSharedSecretRef(r: SecretRef): void { this.sharedSecretRef = r; }
  public setUpdatedAt(d: Date): void { this.updatedAt = d; }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && npm test -- radius-server-profile.entity.spec`
Expected: PASS, 5 cases.

- [ ] **Step 5: Commit**

```bash
git add backend/src/domain/entities/radius-server-profile.entity.ts \
        backend/src/domain/entities/radius-server-profile.entity.spec.ts
git commit -m "feat(identity): add RadiusServerProfile entity"
```

---

### Task 2.2: `LdapServerProfile` entity

**Files:**
- Create: `backend/src/domain/entities/ldap-server-profile.entity.ts`
- Test:   `backend/src/domain/entities/ldap-server-profile.entity.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import { LdapServerProfile } from './ldap-server-profile.entity.js';
import { LdapTlsMode } from '../value-objects/ldap-tls-mode.vo.js';
import { Port } from '../value-objects/port.vo.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';

describe('LdapServerProfile', () => {
  const args = () => ({
    id: '22222222-2222-2222-2222-222222222222',
    name: 'lab-ldap',
    host: '192.168.20.40',
    port: Port.create(389),
    tlsMode: LdapTlsMode.create('none'),
    bindDn: 'cn=admin,dc=raptorgate,dc=local',
    bindPasswordRef: SecretRef.create('secret://ldap-profiles/22222222/bind-password'),
    userBaseDn: 'ou=users,dc=raptorgate,dc=local',
    userFilterAttribute: 'uid',
    groupBaseDn: 'ou=groups,dc=raptorgate,dc=local',
    groupMemberAttribute: 'memberUid',
    groupNameAttribute: 'cn',
    timeoutMs: 3000,
    createdAt: new Date('2026-04-30T00:00:00Z'),
    updatedAt: new Date('2026-04-30T00:00:00Z'),
  });

  it('constructs and exposes getters', () => {
    const a = args();
    const p = LdapServerProfile.create(
      a.id, a.name, a.host, a.port, a.tlsMode, a.bindDn, a.bindPasswordRef,
      a.userBaseDn, a.userFilterAttribute, a.groupBaseDn, a.groupMemberAttribute,
      a.groupNameAttribute, a.timeoutMs, a.createdAt, a.updatedAt,
    );
    expect(p.getId()).toBe(a.id);
    expect(p.getTlsMode().getValue).toBe('none');
    expect(p.getBindDn()).toBe(a.bindDn);
    expect(p.getUserBaseDn()).toBe(a.userBaseDn);
    expect(p.getUserFilterAttribute()).toBe('uid');
    expect(p.getGroupMemberAttribute()).toBe('memberUid');
    expect(p.getGroupNameAttribute()).toBe('cn');
    expect(p.getTimeoutMs()).toBe(3000);
  });

  it('rejects empty bindDn', () => {
    const a = args();
    expect(() => LdapServerProfile.create(
      a.id, a.name, a.host, a.port, a.tlsMode, '', a.bindPasswordRef,
      a.userBaseDn, a.userFilterAttribute, a.groupBaseDn, a.groupMemberAttribute,
      a.groupNameAttribute, a.timeoutMs, a.createdAt, a.updatedAt,
    )).toThrow(/bindDn/i);
  });

  it('rejects empty userBaseDn', () => {
    const a = args();
    expect(() => LdapServerProfile.create(
      a.id, a.name, a.host, a.port, a.tlsMode, a.bindDn, a.bindPasswordRef,
      '', a.userFilterAttribute, a.groupBaseDn, a.groupMemberAttribute,
      a.groupNameAttribute, a.timeoutMs, a.createdAt, a.updatedAt,
    )).toThrow(/userBaseDn/i);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- ldap-server-profile.entity.spec`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement entity**

```typescript
// backend/src/domain/entities/ldap-server-profile.entity.ts
import { LdapTlsMode } from '../value-objects/ldap-tls-mode.vo.js';
import { Port } from '../value-objects/port.vo.js';
import { SecretRef } from '../value-objects/secret-ref.vo.js';

function nonEmpty(label: string, v: string, max: number): void {
  if (!v || v.length === 0 || v.length > max) {
    throw new Error(`LdapServerProfile ${label} must be 1..${max} chars`);
  }
}

export class LdapServerProfile {
  private constructor(
    private readonly id: string,
    private name: string,
    private host: string,
    private port: Port,
    private tlsMode: LdapTlsMode,
    private bindDn: string,
    private bindPasswordRef: SecretRef,
    private userBaseDn: string,
    private userFilterAttribute: string,
    private groupBaseDn: string,
    private groupMemberAttribute: string,
    private groupNameAttribute: string,
    private timeoutMs: number,
    private readonly createdAt: Date,
    private updatedAt: Date,
  ) {}

  public static create(
    id: string,
    name: string,
    host: string,
    port: Port,
    tlsMode: LdapTlsMode,
    bindDn: string,
    bindPasswordRef: SecretRef,
    userBaseDn: string,
    userFilterAttribute: string,
    groupBaseDn: string,
    groupMemberAttribute: string,
    groupNameAttribute: string,
    timeoutMs: number,
    createdAt: Date,
    updatedAt: Date,
  ): LdapServerProfile {
    nonEmpty('name', name, 64);
    nonEmpty('host', host, 253);
    nonEmpty('bindDn', bindDn, 512);
    nonEmpty('userBaseDn', userBaseDn, 512);
    nonEmpty('userFilterAttribute', userFilterAttribute, 64);
    nonEmpty('groupBaseDn', groupBaseDn, 512);
    nonEmpty('groupMemberAttribute', groupMemberAttribute, 64);
    nonEmpty('groupNameAttribute', groupNameAttribute, 64);
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000) {
      throw new Error('LdapServerProfile timeoutMs must be 1..60000');
    }
    return new LdapServerProfile(
      id, name, host, port, tlsMode, bindDn, bindPasswordRef,
      userBaseDn, userFilterAttribute, groupBaseDn, groupMemberAttribute,
      groupNameAttribute, timeoutMs, createdAt, updatedAt,
    );
  }

  public getId(): string { return this.id; }
  public getName(): string { return this.name; }
  public getHost(): string { return this.host; }
  public getPort(): Port { return this.port; }
  public getTlsMode(): LdapTlsMode { return this.tlsMode; }
  public getBindDn(): string { return this.bindDn; }
  public getBindPasswordRef(): SecretRef { return this.bindPasswordRef; }
  public getUserBaseDn(): string { return this.userBaseDn; }
  public getUserFilterAttribute(): string { return this.userFilterAttribute; }
  public getGroupBaseDn(): string { return this.groupBaseDn; }
  public getGroupMemberAttribute(): string { return this.groupMemberAttribute; }
  public getGroupNameAttribute(): string { return this.groupNameAttribute; }
  public getTimeoutMs(): number { return this.timeoutMs; }
  public getCreatedAt(): Date { return this.createdAt; }
  public getUpdatedAt(): Date { return this.updatedAt; }

  public setName(v: string): void { nonEmpty('name', v, 64); this.name = v; }
  public setHost(v: string): void { nonEmpty('host', v, 253); this.host = v; }
  public setPort(v: Port): void { this.port = v; }
  public setTlsMode(v: LdapTlsMode): void { this.tlsMode = v; }
  public setBindDn(v: string): void { nonEmpty('bindDn', v, 512); this.bindDn = v; }
  public setBindPasswordRef(v: SecretRef): void { this.bindPasswordRef = v; }
  public setUserBaseDn(v: string): void { nonEmpty('userBaseDn', v, 512); this.userBaseDn = v; }
  public setUserFilterAttribute(v: string): void { nonEmpty('userFilterAttribute', v, 64); this.userFilterAttribute = v; }
  public setGroupBaseDn(v: string): void { nonEmpty('groupBaseDn', v, 512); this.groupBaseDn = v; }
  public setGroupMemberAttribute(v: string): void { nonEmpty('groupMemberAttribute', v, 64); this.groupMemberAttribute = v; }
  public setGroupNameAttribute(v: string): void { nonEmpty('groupNameAttribute', v, 64); this.groupNameAttribute = v; }
  public setTimeoutMs(v: number): void {
    if (!Number.isInteger(v) || v <= 0 || v > 60000) throw new Error('invalid timeoutMs');
    this.timeoutMs = v;
  }
  public setUpdatedAt(d: Date): void { this.updatedAt = d; }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && npm test -- ldap-server-profile.entity.spec`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/domain/entities/ldap-server-profile.entity.ts \
        backend/src/domain/entities/ldap-server-profile.entity.spec.ts
git commit -m "feat(identity): add LdapServerProfile entity"
```

---

### Task 2.3: `AuthenticationProfile` entity

**Files:**
- Create: `backend/src/domain/entities/authentication-profile.entity.ts`
- Test:   `backend/src/domain/entities/authentication-profile.entity.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import { AuthenticationProfile } from './authentication-profile.entity.js';
import { AuthProviderType } from '../value-objects/auth-provider-type.vo.js';
import { IdentityRoleSource } from '../value-objects/identity-role-source.vo.js';

describe('AuthenticationProfile', () => {
  const dates = { createdAt: new Date('2026-04-30T00:00:00Z'), updatedAt: new Date('2026-04-30T00:00:00Z') };

  it('constructs radius profile with serverProfileId', () => {
    const p = AuthenticationProfile.create(
      'aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      'portal-radius',
      AuthProviderType.create('radius'),
      '11111111-1111-1111-1111-111111111111',
      ['portal-users'],
      IdentityRoleSource.create('radius_vsa'),
      'permissive',
      dates.createdAt, dates.updatedAt,
    );
    expect(p.getName()).toBe('portal-radius');
    expect(p.getProviderType().getValue).toBe('radius');
    expect(p.getServerProfileId()).toBe('11111111-1111-1111-1111-111111111111');
    expect(p.getAllowList()).toEqual(['portal-users']);
    expect(p.getRoleMappingMode()).toBe('permissive');
  });

  it('rejects radius/ldap without serverProfileId', () => {
    expect(() => AuthenticationProfile.create(
      'aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      'portal-radius',
      AuthProviderType.create('radius'),
      null,
      [],
      IdentityRoleSource.create('radius_vsa'),
      'strict',
      dates.createdAt, dates.updatedAt,
    )).toThrow(/serverProfileId/i);
  });

  it('rejects local with serverProfileId set', () => {
    expect(() => AuthenticationProfile.create(
      'aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      'local-admin',
      AuthProviderType.create('local'),
      'should-be-null',
      [],
      IdentityRoleSource.create('local_table'),
      'strict',
      dates.createdAt, dates.updatedAt,
    )).toThrow(/local.*serverProfileId/i);
  });

  it('rejects unknown roleMappingMode', () => {
    expect(() => AuthenticationProfile.create(
      'aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      'portal-radius',
      AuthProviderType.create('radius'),
      '11111111-1111-1111-1111-111111111111',
      [],
      IdentityRoleSource.create('radius_vsa'),
      'lax' as 'strict',
      dates.createdAt, dates.updatedAt,
    )).toThrow(/roleMappingMode/i);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- authentication-profile.entity.spec`
Expected: FAIL.

- [ ] **Step 3: Implement entity**

```typescript
// backend/src/domain/entities/authentication-profile.entity.ts
import { AuthProviderType } from '../value-objects/auth-provider-type.vo.js';
import { IdentityRoleSource } from '../value-objects/identity-role-source.vo.js';

export type RoleMappingMode = 'strict' | 'permissive';
const ALLOWED_MODES: ReadonlySet<RoleMappingMode> = new Set(['strict', 'permissive']);

export class AuthenticationProfile {
  private constructor(
    private readonly id: string,
    private name: string,
    private providerType: AuthProviderType,
    private serverProfileId: string | null,
    private allowList: string[],
    private groupSource: IdentityRoleSource,
    private roleMappingMode: RoleMappingMode,
    private readonly createdAt: Date,
    private updatedAt: Date,
  ) {}

  public static create(
    id: string,
    name: string,
    providerType: AuthProviderType,
    serverProfileId: string | null,
    allowList: string[],
    groupSource: IdentityRoleSource,
    roleMappingMode: RoleMappingMode,
    createdAt: Date,
    updatedAt: Date,
  ): AuthenticationProfile {
    if (!name || name.length === 0 || name.length > 64) {
      throw new Error('AuthenticationProfile name must be 1..64 chars');
    }
    if (providerType.requiresServerProfile() && !serverProfileId) {
      throw new Error(`AuthenticationProfile ${providerType.getValue} requires serverProfileId`);
    }
    if (!providerType.requiresServerProfile() && serverProfileId !== null) {
      throw new Error('AuthenticationProfile local provider must not set serverProfileId');
    }
    if (!ALLOWED_MODES.has(roleMappingMode)) {
      throw new Error(`AuthenticationProfile invalid roleMappingMode: ${roleMappingMode}`);
    }
    return new AuthenticationProfile(
      id, name, providerType, serverProfileId,
      [...allowList], groupSource, roleMappingMode,
      createdAt, updatedAt,
    );
  }

  public getId(): string { return this.id; }
  public getName(): string { return this.name; }
  public getProviderType(): AuthProviderType { return this.providerType; }
  public getServerProfileId(): string | null { return this.serverProfileId; }
  public getAllowList(): string[] { return [...this.allowList]; }
  public getGroupSource(): IdentityRoleSource { return this.groupSource; }
  public getRoleMappingMode(): RoleMappingMode { return this.roleMappingMode; }
  public getCreatedAt(): Date { return this.createdAt; }
  public getUpdatedAt(): Date { return this.updatedAt; }

  public setName(v: string): void {
    if (!v || v.length === 0 || v.length > 64) throw new Error('invalid name');
    this.name = v;
  }
  public setProviderType(v: AuthProviderType): void { this.providerType = v; }
  public setServerProfileId(v: string | null): void { this.serverProfileId = v; }
  public setAllowList(v: string[]): void { this.allowList = [...v]; }
  public setGroupSource(v: IdentityRoleSource): void { this.groupSource = v; }
  public setRoleMappingMode(v: RoleMappingMode): void {
    if (!ALLOWED_MODES.has(v)) throw new Error(`invalid roleMappingMode: ${v}`);
    this.roleMappingMode = v;
  }
  public setUpdatedAt(d: Date): void { this.updatedAt = d; }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && npm test -- authentication-profile.entity.spec`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/domain/entities/authentication-profile.entity.ts \
        backend/src/domain/entities/authentication-profile.entity.spec.ts
git commit -m "feat(identity): add AuthenticationProfile entity"
```

---

### Task 2.4: `IdentitySettings` entity (singleton)

**Files:**
- Create: `backend/src/domain/entities/identity-settings.entity.ts`
- Test:   `backend/src/domain/entities/identity-settings.entity.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
import { IdentitySettings } from './identity-settings.entity.js';

describe('IdentitySettings', () => {
  const updatedAt = new Date('2026-04-30T00:00:00Z');

  it('constructs with all profile ids null', () => {
    const s = IdentitySettings.create(null, null, null, updatedAt);
    expect(s.getPortalAuthProfileId()).toBeNull();
    expect(s.getAdminAuthProfileId()).toBeNull();
    expect(s.getVpnAuthProfileId()).toBeNull();
  });

  it('round-trips ids', () => {
    const s = IdentitySettings.create('portal-id', 'admin-id', null, updatedAt);
    expect(s.getPortalAuthProfileId()).toBe('portal-id');
    expect(s.getAdminAuthProfileId()).toBe('admin-id');
  });

  it('mutates via setters and bumps updatedAt', () => {
    const s = IdentitySettings.create(null, null, null, updatedAt);
    const later = new Date('2026-05-01T00:00:00Z');
    s.setPortalAuthProfileId('p1');
    s.setUpdatedAt(later);
    expect(s.getPortalAuthProfileId()).toBe('p1');
    expect(s.getUpdatedAt()).toEqual(later);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd backend && npm test -- identity-settings.entity.spec`
Expected: FAIL.

- [ ] **Step 3: Implement entity**

```typescript
// backend/src/domain/entities/identity-settings.entity.ts
export class IdentitySettings {
  private constructor(
    private portalAuthProfileId: string | null,
    private adminAuthProfileId: string | null,
    private vpnAuthProfileId: string | null,
    private updatedAt: Date,
  ) {}

  public static create(
    portalAuthProfileId: string | null,
    adminAuthProfileId: string | null,
    vpnAuthProfileId: string | null,
    updatedAt: Date,
  ): IdentitySettings {
    return new IdentitySettings(
      portalAuthProfileId, adminAuthProfileId, vpnAuthProfileId, updatedAt,
    );
  }

  public getPortalAuthProfileId(): string | null { return this.portalAuthProfileId; }
  public getAdminAuthProfileId(): string | null { return this.adminAuthProfileId; }
  public getVpnAuthProfileId(): string | null { return this.vpnAuthProfileId; }
  public getUpdatedAt(): Date { return this.updatedAt; }

  public setPortalAuthProfileId(v: string | null): void { this.portalAuthProfileId = v; }
  public setAdminAuthProfileId(v: string | null): void { this.adminAuthProfileId = v; }
  public setVpnAuthProfileId(v: string | null): void { this.vpnAuthProfileId = v; }
  public setUpdatedAt(v: Date): void { this.updatedAt = v; }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd backend && npm test -- identity-settings.entity.spec`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/domain/entities/identity-settings.entity.ts \
        backend/src/domain/entities/identity-settings.entity.spec.ts
git commit -m "feat(identity): add IdentitySettings singleton entity"
```

---

## Section 3 — Repositories, Schemas, Mappers

### Task 3.1: Repository interfaces

**Files:**
- Create: `backend/src/domain/repositories/radius-server-profile.repository.ts`
- Create: `backend/src/domain/repositories/ldap-server-profile.repository.ts`
- Create: `backend/src/domain/repositories/authentication-profile.repository.ts`
- Create: `backend/src/domain/repositories/identity-settings.repository.ts`

- [ ] **Step 1: Write all four interfaces**

```typescript
// backend/src/domain/repositories/radius-server-profile.repository.ts
import { RadiusServerProfile } from '../entities/radius-server-profile.entity.js';

export interface IRadiusServerProfileRepository {
  save(profile: RadiusServerProfile): Promise<void>;
  findById(id: string): Promise<RadiusServerProfile | null>;
  findByName(name: string): Promise<RadiusServerProfile | null>;
  findAll(): Promise<RadiusServerProfile[]>;
  overwriteAll(profiles: RadiusServerProfile[]): Promise<void>;
  delete(id: string): Promise<void>;
}

export const RADIUS_SERVER_PROFILE_REPOSITORY_TOKEN = Symbol(
  'RADIUS_SERVER_PROFILE_REPOSITORY_TOKEN',
);
```

```typescript
// backend/src/domain/repositories/ldap-server-profile.repository.ts
import { LdapServerProfile } from '../entities/ldap-server-profile.entity.js';

export interface ILdapServerProfileRepository {
  save(profile: LdapServerProfile): Promise<void>;
  findById(id: string): Promise<LdapServerProfile | null>;
  findByName(name: string): Promise<LdapServerProfile | null>;
  findAll(): Promise<LdapServerProfile[]>;
  overwriteAll(profiles: LdapServerProfile[]): Promise<void>;
  delete(id: string): Promise<void>;
}

export const LDAP_SERVER_PROFILE_REPOSITORY_TOKEN = Symbol(
  'LDAP_SERVER_PROFILE_REPOSITORY_TOKEN',
);
```

```typescript
// backend/src/domain/repositories/authentication-profile.repository.ts
import { AuthenticationProfile } from '../entities/authentication-profile.entity.js';

export interface IAuthenticationProfileRepository {
  save(profile: AuthenticationProfile): Promise<void>;
  findById(id: string): Promise<AuthenticationProfile | null>;
  findByName(name: string): Promise<AuthenticationProfile | null>;
  findAll(): Promise<AuthenticationProfile[]>;
  findByServerProfileId(serverProfileId: string): Promise<AuthenticationProfile[]>;
  overwriteAll(profiles: AuthenticationProfile[]): Promise<void>;
  delete(id: string): Promise<void>;
}

export const AUTHENTICATION_PROFILE_REPOSITORY_TOKEN = Symbol(
  'AUTHENTICATION_PROFILE_REPOSITORY_TOKEN',
);
```

```typescript
// backend/src/domain/repositories/identity-settings.repository.ts
import { IdentitySettings } from '../entities/identity-settings.entity.js';

export interface IIdentitySettingsRepository {
  load(): Promise<IdentitySettings>;
  save(settings: IdentitySettings): Promise<void>;
}

export const IDENTITY_SETTINGS_REPOSITORY_TOKEN = Symbol(
  'IDENTITY_SETTINGS_REPOSITORY_TOKEN',
);
```

- [ ] **Step 2: Compile-check**

Run: `cd backend && npx tsc --noEmit`
Expected: succeeds.

- [ ] **Step 3: Commit**

```bash
git add backend/src/domain/repositories/radius-server-profile.repository.ts \
        backend/src/domain/repositories/ldap-server-profile.repository.ts \
        backend/src/domain/repositories/authentication-profile.repository.ts \
        backend/src/domain/repositories/identity-settings.repository.ts
git commit -m "feat(identity): add identity profile repository interfaces"
```

---

### Task 3.2: Zod schemas

**Files:**
- Create: `backend/src/infrastructure/persistence/schemas/radius-server-profiles.schema.ts`
- Create: `backend/src/infrastructure/persistence/schemas/ldap-server-profiles.schema.ts`
- Create: `backend/src/infrastructure/persistence/schemas/authentication-profiles.schema.ts`
- Create: `backend/src/infrastructure/persistence/schemas/identity-settings.schema.ts`

- [ ] **Step 1: Write schemas**

```typescript
// backend/src/infrastructure/persistence/schemas/radius-server-profiles.schema.ts
import { z } from 'zod';
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common.js';

export const RadiusServerProfileRecordSchema = z.object({
  id: uuidSchema,
  name: z.string().min(1).max(64),
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535),
  timeoutMs: z.number().int().min(1).max(60000),
  retries: z.number().int().min(0).max(5),
  nasIp: z.string().max(64).nullable(),
  nasIdentifier: z.string().min(1).max(64),
  authProtocol: z.enum(['pap', 'chap', 'mschapv2']),
  sharedSecretRef: z.string().min(1).max(256),
  createdAt: isoDateTimeSchema,
  updatedAt: isoDateTimeSchema,
}).strict();

export const RadiusServerProfilesFileSchema = tableFileSchema(RadiusServerProfileRecordSchema);
export type RadiusServerProfileRecord = z.infer<typeof RadiusServerProfileRecordSchema>;
export type RadiusServerProfilesFile = z.infer<typeof RadiusServerProfilesFileSchema>;
```

```typescript
// backend/src/infrastructure/persistence/schemas/ldap-server-profiles.schema.ts
import { z } from 'zod';
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common.js';

export const LdapServerProfileRecordSchema = z.object({
  id: uuidSchema,
  name: z.string().min(1).max(64),
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535),
  tlsMode: z.enum(['none', 'starttls', 'ldaps']),
  bindDn: z.string().min(1).max(512),
  bindPasswordRef: z.string().min(1).max(256),
  userBaseDn: z.string().min(1).max(512),
  userFilterAttribute: z.string().min(1).max(64),
  groupBaseDn: z.string().min(1).max(512),
  groupMemberAttribute: z.string().min(1).max(64),
  groupNameAttribute: z.string().min(1).max(64),
  timeoutMs: z.number().int().min(1).max(60000),
  createdAt: isoDateTimeSchema,
  updatedAt: isoDateTimeSchema,
}).strict();

export const LdapServerProfilesFileSchema = tableFileSchema(LdapServerProfileRecordSchema);
export type LdapServerProfileRecord = z.infer<typeof LdapServerProfileRecordSchema>;
export type LdapServerProfilesFile = z.infer<typeof LdapServerProfilesFileSchema>;
```

```typescript
// backend/src/infrastructure/persistence/schemas/authentication-profiles.schema.ts
import { z } from 'zod';
import { isoDateTimeSchema, tableFileSchema, uuidSchema } from './_common.js';

export const AuthenticationProfileRecordSchema = z.object({
  id: uuidSchema,
  name: z.string().min(1).max(64),
  providerType: z.enum(['radius', 'ldap', 'local']),
  serverProfileId: uuidSchema.nullable(),
  allowList: z.array(z.string().min(1).max(128)).max(256),
  groupSource: z.enum(['ldap', 'radius_vsa', 'local_table']),
  roleMappingMode: z.enum(['strict', 'permissive']),
  createdAt: isoDateTimeSchema,
  updatedAt: isoDateTimeSchema,
}).strict();

export const AuthenticationProfilesFileSchema = tableFileSchema(AuthenticationProfileRecordSchema);
export type AuthenticationProfileRecord = z.infer<typeof AuthenticationProfileRecordSchema>;
export type AuthenticationProfilesFile = z.infer<typeof AuthenticationProfilesFileSchema>;
```

```typescript
// backend/src/infrastructure/persistence/schemas/identity-settings.schema.ts
import { z } from 'zod';
import { isoDateTimeSchema, uuidSchema } from './_common.js';

export const IdentitySettingsFileSchema = z.object({
  portalAuthProfileId: uuidSchema.nullable(),
  adminAuthProfileId: uuidSchema.nullable(),
  vpnAuthProfileId: uuidSchema.nullable(),
  updatedAt: isoDateTimeSchema,
}).strict();

export type IdentitySettingsFile = z.infer<typeof IdentitySettingsFileSchema>;
```

- [ ] **Step 2: Type-check**

Run: `cd backend && npx tsc --noEmit`
Expected: succeeds.

- [ ] **Step 3: Commit**

```bash
git add backend/src/infrastructure/persistence/schemas/radius-server-profiles.schema.ts \
        backend/src/infrastructure/persistence/schemas/ldap-server-profiles.schema.ts \
        backend/src/infrastructure/persistence/schemas/authentication-profiles.schema.ts \
        backend/src/infrastructure/persistence/schemas/identity-settings.schema.ts
git commit -m "feat(identity): add JSON schemas for identity profiles"
```

---

### Task 3.3: JSON mappers

**Files:**
- Create: `backend/src/infrastructure/persistence/mappers/radius-server-profile-json.mapper.ts`
- Create: `backend/src/infrastructure/persistence/mappers/radius-server-profile-json.mapper.spec.ts`
- Create: `backend/src/infrastructure/persistence/mappers/ldap-server-profile-json.mapper.ts`
- Create: `backend/src/infrastructure/persistence/mappers/ldap-server-profile-json.mapper.spec.ts`
- Create: `backend/src/infrastructure/persistence/mappers/authentication-profile-json.mapper.ts`
- Create: `backend/src/infrastructure/persistence/mappers/authentication-profile-json.mapper.spec.ts`
- Create: `backend/src/infrastructure/persistence/mappers/identity-settings-json.mapper.ts`
- Create: `backend/src/infrastructure/persistence/mappers/identity-settings-json.mapper.spec.ts`

- [ ] **Step 1: Write the failing tests for radius mapper**

```typescript
// backend/src/infrastructure/persistence/mappers/radius-server-profile-json.mapper.spec.ts
import { RadiusServerProfile } from '../../../domain/entities/radius-server-profile.entity.js';
import { AuthProtocol } from '../../../domain/value-objects/auth-protocol.vo.js';
import { IpAddress } from '../../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../../domain/value-objects/port.vo.js';
import { SecretRef } from '../../../domain/value-objects/secret-ref.vo.js';
import { RadiusServerProfileJsonMapper } from './radius-server-profile-json.mapper.js';

describe('RadiusServerProfileJsonMapper', () => {
  const sample = () => RadiusServerProfile.create(
    '11111111-1111-1111-1111-111111111111',
    'lab-radius',
    '192.168.20.30',
    Port.create(1812),
    3000,
    1,
    IpAddress.create('192.168.20.254'),
    'raptorgate-backend',
    AuthProtocol.create('pap'),
    SecretRef.create('secret://radius-profiles/11111111/shared-secret'),
    new Date('2026-04-30T00:00:00Z'),
    new Date('2026-04-30T00:00:00Z'),
  );

  it('round-trips entity through record', () => {
    const entity = sample();
    const record = RadiusServerProfileJsonMapper.toRecord(entity);
    const back = RadiusServerProfileJsonMapper.toDomain(record);
    expect(back.getId()).toBe(entity.getId());
    expect(back.getName()).toBe(entity.getName());
    expect(back.getHost()).toBe(entity.getHost());
    expect(back.getPort().getValue).toBe(1812);
    expect(back.getTimeoutMs()).toBe(3000);
    expect(back.getRetries()).toBe(1);
    expect(back.getNasIp()?.getValue).toBe('192.168.20.254');
    expect(back.getAuthProtocol().getValue).toBe('pap');
    expect(back.getSharedSecretRef().getValue).toBe('secret://radius-profiles/11111111/shared-secret');
  });

  it('handles null nasIp', () => {
    const entity = RadiusServerProfile.create(
      '11111111-1111-1111-1111-111111111111',
      'lab-radius', '192.168.20.30', Port.create(1812), 3000, 1,
      null, 'nas',
      AuthProtocol.create('pap'),
      SecretRef.create('secret://radius-profiles/11111111/shared-secret'),
      new Date('2026-04-30T00:00:00Z'), new Date('2026-04-30T00:00:00Z'),
    );
    const record = RadiusServerProfileJsonMapper.toRecord(entity);
    expect(record.nasIp).toBeNull();
    const back = RadiusServerProfileJsonMapper.toDomain(record);
    expect(back.getNasIp()).toBeNull();
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `cd backend && npm test -- radius-server-profile-json.mapper.spec`
Expected: FAIL.

- [ ] **Step 3: Implement radius mapper**

```typescript
// backend/src/infrastructure/persistence/mappers/radius-server-profile-json.mapper.ts
import { RadiusServerProfile } from '../../../domain/entities/radius-server-profile.entity.js';
import { AuthProtocol } from '../../../domain/value-objects/auth-protocol.vo.js';
import { IpAddress } from '../../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../../domain/value-objects/port.vo.js';
import { SecretRef } from '../../../domain/value-objects/secret-ref.vo.js';
import { RadiusServerProfileRecord } from '../schemas/radius-server-profiles.schema.js';

export class RadiusServerProfileJsonMapper {
  static toDomain(record: RadiusServerProfileRecord): RadiusServerProfile {
    return RadiusServerProfile.create(
      record.id,
      record.name,
      record.host,
      Port.create(record.port),
      record.timeoutMs,
      record.retries,
      record.nasIp ? IpAddress.create(record.nasIp) : null,
      record.nasIdentifier,
      AuthProtocol.create(record.authProtocol),
      SecretRef.create(record.sharedSecretRef),
      new Date(record.createdAt),
      new Date(record.updatedAt),
    );
  }

  static toRecord(profile: RadiusServerProfile): RadiusServerProfileRecord {
    return {
      id: profile.getId(),
      name: profile.getName(),
      host: profile.getHost(),
      port: profile.getPort().getValue,
      timeoutMs: profile.getTimeoutMs(),
      retries: profile.getRetries(),
      nasIp: profile.getNasIp()?.getValue ?? null,
      nasIdentifier: profile.getNasIdentifier(),
      authProtocol: profile.getAuthProtocol().getValue,
      sharedSecretRef: profile.getSharedSecretRef().getValue,
      createdAt: profile.getCreatedAt().toISOString(),
      updatedAt: profile.getUpdatedAt().toISOString(),
    };
  }
}
```

- [ ] **Step 4: Run, expect PASS**

Run: `cd backend && npm test -- radius-server-profile-json.mapper.spec`
Expected: PASS.

- [ ] **Step 5: Repeat the (test → fail → impl → pass) sequence for the LDAP mapper**

```typescript
// backend/src/infrastructure/persistence/mappers/ldap-server-profile-json.mapper.spec.ts
import { LdapServerProfile } from '../../../domain/entities/ldap-server-profile.entity.js';
import { LdapTlsMode } from '../../../domain/value-objects/ldap-tls-mode.vo.js';
import { Port } from '../../../domain/value-objects/port.vo.js';
import { SecretRef } from '../../../domain/value-objects/secret-ref.vo.js';
import { LdapServerProfileJsonMapper } from './ldap-server-profile-json.mapper.js';

describe('LdapServerProfileJsonMapper', () => {
  it('round-trips', () => {
    const e = LdapServerProfile.create(
      '22222222-2222-2222-2222-222222222222',
      'lab-ldap', '192.168.20.40',
      Port.create(389),
      LdapTlsMode.create('starttls'),
      'cn=admin,dc=raptorgate,dc=local',
      SecretRef.create('secret://ldap-profiles/22222222/bind-password'),
      'ou=users,dc=raptorgate,dc=local', 'uid',
      'ou=groups,dc=raptorgate,dc=local', 'memberUid', 'cn',
      3000,
      new Date('2026-04-30T00:00:00Z'), new Date('2026-04-30T00:00:00Z'),
    );
    const r = LdapServerProfileJsonMapper.toRecord(e);
    const back = LdapServerProfileJsonMapper.toDomain(r);
    expect(back.getId()).toBe(e.getId());
    expect(back.getTlsMode().getValue).toBe('starttls');
    expect(back.getGroupMemberAttribute()).toBe('memberUid');
    expect(back.getBindPasswordRef().getValue).toBe(e.getBindPasswordRef().getValue);
  });
});
```

```typescript
// backend/src/infrastructure/persistence/mappers/ldap-server-profile-json.mapper.ts
import { LdapServerProfile } from '../../../domain/entities/ldap-server-profile.entity.js';
import { LdapTlsMode } from '../../../domain/value-objects/ldap-tls-mode.vo.js';
import { Port } from '../../../domain/value-objects/port.vo.js';
import { SecretRef } from '../../../domain/value-objects/secret-ref.vo.js';
import { LdapServerProfileRecord } from '../schemas/ldap-server-profiles.schema.js';

export class LdapServerProfileJsonMapper {
  static toDomain(r: LdapServerProfileRecord): LdapServerProfile {
    return LdapServerProfile.create(
      r.id, r.name, r.host, Port.create(r.port), LdapTlsMode.create(r.tlsMode),
      r.bindDn, SecretRef.create(r.bindPasswordRef),
      r.userBaseDn, r.userFilterAttribute,
      r.groupBaseDn, r.groupMemberAttribute, r.groupNameAttribute,
      r.timeoutMs,
      new Date(r.createdAt), new Date(r.updatedAt),
    );
  }
  static toRecord(p: LdapServerProfile): LdapServerProfileRecord {
    return {
      id: p.getId(), name: p.getName(), host: p.getHost(),
      port: p.getPort().getValue,
      tlsMode: p.getTlsMode().getValue,
      bindDn: p.getBindDn(),
      bindPasswordRef: p.getBindPasswordRef().getValue,
      userBaseDn: p.getUserBaseDn(),
      userFilterAttribute: p.getUserFilterAttribute(),
      groupBaseDn: p.getGroupBaseDn(),
      groupMemberAttribute: p.getGroupMemberAttribute(),
      groupNameAttribute: p.getGroupNameAttribute(),
      timeoutMs: p.getTimeoutMs(),
      createdAt: p.getCreatedAt().toISOString(),
      updatedAt: p.getUpdatedAt().toISOString(),
    };
  }
}
```

- [ ] **Step 6: Repeat (test → fail → impl → pass) for AuthenticationProfile mapper**

```typescript
// backend/src/infrastructure/persistence/mappers/authentication-profile-json.mapper.spec.ts
import { AuthenticationProfile } from '../../../domain/entities/authentication-profile.entity.js';
import { AuthProviderType } from '../../../domain/value-objects/auth-provider-type.vo.js';
import { IdentityRoleSource } from '../../../domain/value-objects/identity-role-source.vo.js';
import { AuthenticationProfileJsonMapper } from './authentication-profile-json.mapper.js';

describe('AuthenticationProfileJsonMapper', () => {
  it('round-trips radius profile', () => {
    const e = AuthenticationProfile.create(
      'aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      'portal-radius',
      AuthProviderType.create('radius'),
      '11111111-1111-1111-1111-111111111111',
      ['portal-users'],
      IdentityRoleSource.create('radius_vsa'),
      'permissive',
      new Date('2026-04-30T00:00:00Z'),
      new Date('2026-04-30T00:00:00Z'),
    );
    const r = AuthenticationProfileJsonMapper.toRecord(e);
    const back = AuthenticationProfileJsonMapper.toDomain(r);
    expect(back.getProviderType().getValue).toBe('radius');
    expect(back.getServerProfileId()).toBe('11111111-1111-1111-1111-111111111111');
    expect(back.getAllowList()).toEqual(['portal-users']);
    expect(back.getRoleMappingMode()).toBe('permissive');
  });
});
```

```typescript
// backend/src/infrastructure/persistence/mappers/authentication-profile-json.mapper.ts
import { AuthenticationProfile, RoleMappingMode } from '../../../domain/entities/authentication-profile.entity.js';
import { AuthProviderType } from '../../../domain/value-objects/auth-provider-type.vo.js';
import { IdentityRoleSource } from '../../../domain/value-objects/identity-role-source.vo.js';
import { AuthenticationProfileRecord } from '../schemas/authentication-profiles.schema.js';

export class AuthenticationProfileJsonMapper {
  static toDomain(r: AuthenticationProfileRecord): AuthenticationProfile {
    return AuthenticationProfile.create(
      r.id, r.name,
      AuthProviderType.create(r.providerType),
      r.serverProfileId,
      r.allowList,
      IdentityRoleSource.create(r.groupSource),
      r.roleMappingMode as RoleMappingMode,
      new Date(r.createdAt), new Date(r.updatedAt),
    );
  }
  static toRecord(p: AuthenticationProfile): AuthenticationProfileRecord {
    return {
      id: p.getId(),
      name: p.getName(),
      providerType: p.getProviderType().getValue,
      serverProfileId: p.getServerProfileId(),
      allowList: p.getAllowList(),
      groupSource: p.getGroupSource().getValue,
      roleMappingMode: p.getRoleMappingMode(),
      createdAt: p.getCreatedAt().toISOString(),
      updatedAt: p.getUpdatedAt().toISOString(),
    };
  }
}
```

- [ ] **Step 7: Repeat (test → fail → impl → pass) for IdentitySettings mapper**

```typescript
// backend/src/infrastructure/persistence/mappers/identity-settings-json.mapper.spec.ts
import { IdentitySettings } from '../../../domain/entities/identity-settings.entity.js';
import { IdentitySettingsJsonMapper } from './identity-settings-json.mapper.js';

describe('IdentitySettingsJsonMapper', () => {
  it('round-trips', () => {
    const e = IdentitySettings.create(
      'aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      null, null,
      new Date('2026-04-30T00:00:00Z'),
    );
    const r = IdentitySettingsJsonMapper.toRecord(e);
    const back = IdentitySettingsJsonMapper.toDomain(r);
    expect(back.getPortalAuthProfileId()).toBe('aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    expect(back.getAdminAuthProfileId()).toBeNull();
  });
});
```

```typescript
// backend/src/infrastructure/persistence/mappers/identity-settings-json.mapper.ts
import { IdentitySettings } from '../../../domain/entities/identity-settings.entity.js';
import { IdentitySettingsFile } from '../schemas/identity-settings.schema.js';

export class IdentitySettingsJsonMapper {
  static toDomain(r: IdentitySettingsFile): IdentitySettings {
    return IdentitySettings.create(
      r.portalAuthProfileId,
      r.adminAuthProfileId,
      r.vpnAuthProfileId,
      new Date(r.updatedAt),
    );
  }
  static toRecord(s: IdentitySettings): IdentitySettingsFile {
    return {
      portalAuthProfileId: s.getPortalAuthProfileId(),
      adminAuthProfileId: s.getAdminAuthProfileId(),
      vpnAuthProfileId: s.getVpnAuthProfileId(),
      updatedAt: s.getUpdatedAt().toISOString(),
    };
  }
}
```

- [ ] **Step 8: Run all four mapper tests**

Run: `cd backend && npm test -- json.mapper.spec`
Expected: 4 mapper suites PASS.

- [ ] **Step 9: Commit**

```bash
git add backend/src/infrastructure/persistence/mappers/radius-server-profile-json.mapper.ts \
        backend/src/infrastructure/persistence/mappers/radius-server-profile-json.mapper.spec.ts \
        backend/src/infrastructure/persistence/mappers/ldap-server-profile-json.mapper.ts \
        backend/src/infrastructure/persistence/mappers/ldap-server-profile-json.mapper.spec.ts \
        backend/src/infrastructure/persistence/mappers/authentication-profile-json.mapper.ts \
        backend/src/infrastructure/persistence/mappers/authentication-profile-json.mapper.spec.ts \
        backend/src/infrastructure/persistence/mappers/identity-settings-json.mapper.ts \
        backend/src/infrastructure/persistence/mappers/identity-settings-json.mapper.spec.ts
git commit -m "feat(identity): add JSON mappers for identity profiles"
```

---

### Task 3.4: JSON repository implementations

**Files:**
- Create: `backend/src/infrastructure/persistence/repositories/json-radius-server-profile.repository.ts`
- Create: `backend/src/infrastructure/persistence/repositories/json-ldap-server-profile.repository.ts`
- Create: `backend/src/infrastructure/persistence/repositories/json-authentication-profile.repository.ts`
- Create: `backend/src/infrastructure/persistence/repositories/json-identity-settings.repository.ts`

- [ ] **Step 1: Implement `JsonRadiusServerProfileRepository`**

```typescript
// backend/src/infrastructure/persistence/repositories/json-radius-server-profile.repository.ts
import { join } from 'node:path';
import { Inject, Injectable } from '@nestjs/common';
import { RadiusServerProfile } from '../../../domain/entities/radius-server-profile.entity.js';
import { IRadiusServerProfileRepository } from '../../../domain/repositories/radius-server-profile.repository.js';
import { RadiusServerProfileJsonMapper } from '../mappers/radius-server-profile-json.mapper.js';
import {
  RadiusServerProfilesFile,
  RadiusServerProfilesFileSchema,
} from '../schemas/radius-server-profiles.schema.js';
import { Mutex } from '../json/file-mutex.js';
import { FileStore } from '../json/file-store.js';

@Injectable()
export class JsonRadiusServerProfileRepository implements IRadiusServerProfileRepository {
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/radius_server_profiles.json',
  );

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<RadiusServerProfilesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, { items: [] });
    return RadiusServerProfilesFileSchema.parse(raw);
  }

  async save(profile: RadiusServerProfile): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      const idx = payload.items.findIndex((i) => i.id === profile.getId());
      const next = RadiusServerProfileJsonMapper.toRecord(profile);
      if (idx >= 0) payload.items[idx] = next;
      else payload.items.push(next);
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async findById(id: string): Promise<RadiusServerProfile | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((i) => i.id === id);
    return row ? RadiusServerProfileJsonMapper.toDomain(row) : null;
  }

  async findByName(name: string): Promise<RadiusServerProfile | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((i) => i.name === name);
    return row ? RadiusServerProfileJsonMapper.toDomain(row) : null;
  }

  async findAll(): Promise<RadiusServerProfile[]> {
    const payload = await this.readPayload();
    return payload.items.map((i) => RadiusServerProfileJsonMapper.toDomain(i));
  }

  async overwriteAll(profiles: RadiusServerProfile[]): Promise<void> {
    const items = profiles.map((p) => RadiusServerProfileJsonMapper.toRecord(p));
    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, { items });
    });
  }

  async delete(id: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      payload.items = payload.items.filter((i) => i.id !== id);
      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
```

- [ ] **Step 2: Implement the three sibling repositories with the same shape**

`JsonLdapServerProfileRepository` — file `data/json-db/ldap_server_profiles.json`, types from `ldap-server-profiles.schema.js`, mapper `LdapServerProfileJsonMapper`.

`JsonAuthenticationProfileRepository` — file `data/json-db/authentication_profiles.json`. Add `findByServerProfileId(id)` that filters by `serverProfileId`.

`JsonIdentitySettingsRepository` — singleton:

```typescript
// backend/src/infrastructure/persistence/repositories/json-identity-settings.repository.ts
import { join } from 'node:path';
import { Inject, Injectable } from '@nestjs/common';
import { IdentitySettings } from '../../../domain/entities/identity-settings.entity.js';
import { IIdentitySettingsRepository } from '../../../domain/repositories/identity-settings.repository.js';
import { IdentitySettingsJsonMapper } from '../mappers/identity-settings-json.mapper.js';
import { IdentitySettingsFileSchema } from '../schemas/identity-settings.schema.js';
import { Mutex } from '../json/file-mutex.js';
import { FileStore } from '../json/file-store.js';

@Injectable()
export class JsonIdentitySettingsRepository implements IIdentitySettingsRepository {
  private readonly filePath = join(process.cwd(), 'data/json-db/identity_settings.json');

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  async load(): Promise<IdentitySettings> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      portalAuthProfileId: null,
      adminAuthProfileId: null,
      vpnAuthProfileId: null,
      updatedAt: new Date(0).toISOString(),
    });
    const parsed = IdentitySettingsFileSchema.parse(raw);
    return IdentitySettingsJsonMapper.toDomain(parsed);
  }

  async save(settings: IdentitySettings): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const record = IdentitySettingsJsonMapper.toRecord(settings);
      await this.fileStore.writeJsonAtomic(this.filePath, record);
    });
  }
}
```

- [ ] **Step 3: Wire DI**

Locate the NestJS module that registers `JsonNatRuleRepository`:

Run: `grep -rn "JsonNatRuleRepository" backend/src/`

In each module file that registers `JsonNatRuleRepository`, register the four new repositories using their tokens:

```typescript
{
  provide: RADIUS_SERVER_PROFILE_REPOSITORY_TOKEN,
  useClass: JsonRadiusServerProfileRepository,
},
{
  provide: LDAP_SERVER_PROFILE_REPOSITORY_TOKEN,
  useClass: JsonLdapServerProfileRepository,
},
{
  provide: AUTHENTICATION_PROFILE_REPOSITORY_TOKEN,
  useClass: JsonAuthenticationProfileRepository,
},
{
  provide: IDENTITY_SETTINGS_REPOSITORY_TOKEN,
  useClass: JsonIdentitySettingsRepository,
},
```

Add the matching tokens/classes to `exports` if and only if `NAT_RULES_REPOSITORY_TOKEN` is exported.

- [ ] **Step 4: Type-check + run all backend tests**

Run: `cd backend && npx tsc --noEmit && npm test`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add backend/src/infrastructure/persistence/repositories/json-radius-server-profile.repository.ts \
        backend/src/infrastructure/persistence/repositories/json-ldap-server-profile.repository.ts \
        backend/src/infrastructure/persistence/repositories/json-authentication-profile.repository.ts \
        backend/src/infrastructure/persistence/repositories/json-identity-settings.repository.ts \
        backend/src/<modules where DI was wired>
git commit -m "feat(identity): add JSON repositories for identity profiles"
```

---

## Section 4 — Referential integrity

### Task 4.1: `IdentityProfileInUseException`

**Files:**
- Create: `backend/src/domain/exceptions/identity-profile-in-use.exception.ts`

- [ ] **Step 1: Implement**

```typescript
// backend/src/domain/exceptions/identity-profile-in-use.exception.ts
export class IdentityProfileInUseException extends Error {
  public readonly references: string[];

  constructor(
    public readonly profileType: 'radius' | 'ldap' | 'authentication',
    public readonly profileId: string,
    references: string[],
  ) {
    super(
      `Cannot delete ${profileType} profile ${profileId}: still referenced by ${references.length} object(s)`,
    );
    this.name = 'IdentityProfileInUseException';
    this.references = references;
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add backend/src/domain/exceptions/identity-profile-in-use.exception.ts
git commit -m "feat(identity): add IdentityProfileInUseException"
```

---

### Task 4.2: `IdentityReferentialIntegrityService`

**Files:**
- Create: `backend/src/application/services/identity-referential-integrity.service.ts`
- Test:   `backend/src/application/services/identity-referential-integrity.service.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// backend/src/application/services/identity-referential-integrity.service.spec.ts
import { IdentityReferentialIntegrityService } from './identity-referential-integrity.service.js';
import { AuthenticationProfile } from '../../domain/entities/authentication-profile.entity.js';
import { AuthProviderType } from '../../domain/value-objects/auth-provider-type.vo.js';
import { IdentityRoleSource } from '../../domain/value-objects/identity-role-source.vo.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { IdentityProfileInUseException } from '../../domain/exceptions/identity-profile-in-use.exception.js';

const D = (s: string) => new Date(s);

function authProfile(id: string, serverProfileId: string | null, type: 'radius' | 'ldap' | 'local' = 'radius') {
  return AuthenticationProfile.create(
    id,
    `prof-${id}`,
    AuthProviderType.create(type),
    serverProfileId,
    [],
    IdentityRoleSource.create(type === 'ldap' ? 'ldap' : 'radius_vsa'),
    'strict',
    D('2026-04-30T00:00:00Z'), D('2026-04-30T00:00:00Z'),
  );
}

describe('IdentityReferentialIntegrityService', () => {
  it('throws when deleting a radius profile referenced by an auth profile', async () => {
    const authRepo = {
      findByServerProfileId: jest.fn().mockResolvedValue([authProfile('aa11', '11111111-1111-1111-1111-111111111111')]),
    } as any;
    const settingsRepo = { load: jest.fn() } as any;
    const svc = new IdentityReferentialIntegrityService(authRepo, settingsRepo);
    await expect(svc.assertRadiusProfileDeletable('11111111-1111-1111-1111-111111111111'))
      .rejects.toBeInstanceOf(IdentityProfileInUseException);
  });

  it('passes when no references exist', async () => {
    const authRepo = { findByServerProfileId: jest.fn().mockResolvedValue([]) } as any;
    const settingsRepo = { load: jest.fn() } as any;
    const svc = new IdentityReferentialIntegrityService(authRepo, settingsRepo);
    await expect(svc.assertRadiusProfileDeletable('11111111-1111-1111-1111-111111111111')).resolves.toBeUndefined();
  });

  it('throws when deleting an authentication profile referenced by identity settings (portal)', async () => {
    const authRepo = { findByServerProfileId: jest.fn() } as any;
    const settingsRepo = {
      load: jest.fn().mockResolvedValue(IdentitySettings.create('aa11', null, null, D('2026-04-30T00:00:00Z'))),
    } as any;
    const svc = new IdentityReferentialIntegrityService(authRepo, settingsRepo);
    await expect(svc.assertAuthenticationProfileDeletable('aa11'))
      .rejects.toBeInstanceOf(IdentityProfileInUseException);
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `cd backend && npm test -- identity-referential-integrity.service.spec`
Expected: FAIL.

- [ ] **Step 3: Implement service**

```typescript
// backend/src/application/services/identity-referential-integrity.service.ts
import { Inject, Injectable } from '@nestjs/common';
import { IdentityProfileInUseException } from '../../domain/exceptions/identity-profile-in-use.exception.js';
import {
  AUTHENTICATION_PROFILE_REPOSITORY_TOKEN,
  type IAuthenticationProfileRepository,
} from '../../domain/repositories/authentication-profile.repository.js';
import {
  IDENTITY_SETTINGS_REPOSITORY_TOKEN,
  type IIdentitySettingsRepository,
} from '../../domain/repositories/identity-settings.repository.js';

@Injectable()
export class IdentityReferentialIntegrityService {
  constructor(
    @Inject(AUTHENTICATION_PROFILE_REPOSITORY_TOKEN)
    private readonly authRepo: IAuthenticationProfileRepository,
    @Inject(IDENTITY_SETTINGS_REPOSITORY_TOKEN)
    private readonly settingsRepo: IIdentitySettingsRepository,
  ) {}

  async assertRadiusProfileDeletable(serverProfileId: string): Promise<void> {
    const refs = await this.authRepo.findByServerProfileId(serverProfileId);
    if (refs.length > 0) {
      throw new IdentityProfileInUseException(
        'radius',
        serverProfileId,
        refs.map((r) => r.getId()),
      );
    }
  }

  async assertLdapProfileDeletable(serverProfileId: string): Promise<void> {
    const refs = await this.authRepo.findByServerProfileId(serverProfileId);
    if (refs.length > 0) {
      throw new IdentityProfileInUseException(
        'ldap',
        serverProfileId,
        refs.map((r) => r.getId()),
      );
    }
  }

  async assertAuthenticationProfileDeletable(profileId: string): Promise<void> {
    const settings = await this.settingsRepo.load();
    const refs: string[] = [];
    if (settings.getPortalAuthProfileId() === profileId) refs.push('identity-settings:portal');
    if (settings.getAdminAuthProfileId() === profileId) refs.push('identity-settings:admin');
    if (settings.getVpnAuthProfileId() === profileId) refs.push('identity-settings:vpn');
    if (refs.length > 0) {
      throw new IdentityProfileInUseException('authentication', profileId, refs);
    }
  }
}
```

- [ ] **Step 4: Run, expect PASS**

Run: `cd backend && npm test -- identity-referential-integrity.service.spec`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/application/services/identity-referential-integrity.service.ts \
        backend/src/application/services/identity-referential-integrity.service.spec.ts
git commit -m "feat(identity): add referential integrity service"
```

---

## Section 5 — Bootstrap seed from env (legacy compatibility)

### Task 5.1: `IdentityBootstrapSeedService`

**Goal:** On NestJS module init, if `radius_server_profiles.json` is empty, seed one profile from the existing env (`RADIUS_*`). Same for LDAP. Same for authentication profiles + identity settings (portal-radius, admin-local). This keeps the lab working while making env stop being source of truth: the next snapshot apply persists what is in the JSON store; subsequent edits go through (future) Issue C admin API. Env stays as bootstrap default seed only.

**Files:**
- Create: `backend/src/application/services/identity-bootstrap-seed.service.ts`
- Test:   `backend/src/application/services/identity-bootstrap-seed.service.spec.ts`

- [ ] **Step 1: Write the failing test**

```typescript
// backend/src/application/services/identity-bootstrap-seed.service.spec.ts
import { IdentityBootstrapSeedService } from './identity-bootstrap-seed.service.js';

describe('IdentityBootstrapSeedService', () => {
  function makeRepo<T>() {
    const items: T[] = [];
    return {
      findAll: jest.fn(async () => [...items]),
      save: jest.fn(async (x: T) => { items.push(x); }),
      load: jest.fn(),
    } as any;
  }

  const env = {
    get: (key: string) => ({
      RADIUS_HOST: '192.168.20.30',
      RADIUS_PORT: 1812,
      RADIUS_TIMEOUT_MS: 3000,
      RADIUS_RETRIES: 1,
      RADIUS_NAS_IP: '192.168.20.254',
      RADIUS_NAS_IDENTIFIER: 'raptorgate-backend',
      IDENTITY_LDAP_HOST: '192.168.20.40',
      IDENTITY_LDAP_PORT: 389,
      IDENTITY_LDAP_BIND_DN: 'cn=admin,dc=raptorgate,dc=local',
      IDENTITY_LDAP_USER_BASE_DN: 'ou=users,dc=raptorgate,dc=local',
      IDENTITY_LDAP_USER_FILTER_ATTRIBUTE: 'uid',
      IDENTITY_LDAP_GROUP_BASE_DN: 'ou=groups,dc=raptorgate,dc=local',
      IDENTITY_LDAP_GROUP_MEMBER_ATTRIBUTE: 'memberUid',
      IDENTITY_LDAP_GROUP_NAME_ATTRIBUTE: 'cn',
      IDENTITY_LDAP_TIMEOUT_MS: 3000,
    } as Record<string, unknown>)[key],
  } as any;

  it('seeds RADIUS, LDAP, authentication profiles + identity settings when empty', async () => {
    const radius = makeRepo();
    const ldap = makeRepo();
    const auth = makeRepo();
    const settings = (() => {
      let stored: any = null;
      return {
        load: jest.fn(async () => stored ?? {
          getPortalAuthProfileId: () => null,
          getAdminAuthProfileId: () => null,
          getVpnAuthProfileId: () => null,
          getUpdatedAt: () => new Date(0),
        }),
        save: jest.fn(async (s: any) => { stored = s; }),
      } as any;
    })();

    const svc = new IdentityBootstrapSeedService(env, radius, ldap, auth, settings);
    await svc.onModuleInit();

    expect(radius.save).toHaveBeenCalledTimes(1);
    expect(ldap.save).toHaveBeenCalledTimes(1);
    expect(auth.save).toHaveBeenCalledTimes(2);
    expect(settings.save).toHaveBeenCalledTimes(1);
  });

  it('does not re-seed when RADIUS profiles already exist', async () => {
    const radius = makeRepo();
    radius.findAll = jest.fn(async () => [{}]);
    const ldap = makeRepo();
    const auth = makeRepo();
    const settings = { load: jest.fn(async () => ({
      getPortalAuthProfileId: () => 'x',
      getAdminAuthProfileId: () => 'y',
      getVpnAuthProfileId: () => null,
      getUpdatedAt: () => new Date(0),
    })), save: jest.fn() } as any;

    const svc = new IdentityBootstrapSeedService(env, radius, ldap, auth, settings);
    await svc.onModuleInit();

    expect(radius.save).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run, expect FAIL**

Run: `cd backend && npm test -- identity-bootstrap-seed.service.spec`
Expected: FAIL.

- [ ] **Step 3: Implement service**

```typescript
// backend/src/application/services/identity-bootstrap-seed.service.ts
import { randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthenticationProfile } from '../../domain/entities/authentication-profile.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import {
  AUTHENTICATION_PROFILE_REPOSITORY_TOKEN,
  type IAuthenticationProfileRepository,
} from '../../domain/repositories/authentication-profile.repository.js';
import {
  IDENTITY_SETTINGS_REPOSITORY_TOKEN,
  type IIdentitySettingsRepository,
} from '../../domain/repositories/identity-settings.repository.js';
import {
  LDAP_SERVER_PROFILE_REPOSITORY_TOKEN,
  type ILdapServerProfileRepository,
} from '../../domain/repositories/ldap-server-profile.repository.js';
import {
  RADIUS_SERVER_PROFILE_REPOSITORY_TOKEN,
  type IRadiusServerProfileRepository,
} from '../../domain/repositories/radius-server-profile.repository.js';
import { AuthProtocol } from '../../domain/value-objects/auth-protocol.vo.js';
import { AuthProviderType } from '../../domain/value-objects/auth-provider-type.vo.js';
import { IdentityRoleSource } from '../../domain/value-objects/identity-role-source.vo.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { LdapTlsMode } from '../../domain/value-objects/ldap-tls-mode.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { SecretRef } from '../../domain/value-objects/secret-ref.vo.js';
import type { Env } from '../../shared/config/env.validation.js';

// Bootstrap z env -> JSON store wykonywany raz, przy pustym storze.
// Po pierwszym uruchomieniu env staje sie tylko domyslnym seedem; admin
// edytuje profile przez API (Issue C), nie przez restart z innym env.
@Injectable()
export class IdentityBootstrapSeedService implements OnModuleInit {
  private readonly logger = new Logger(IdentityBootstrapSeedService.name);

  constructor(
    @Inject(ConfigService)
    private readonly configService: ConfigService<Env, true>,
    @Inject(RADIUS_SERVER_PROFILE_REPOSITORY_TOKEN)
    private readonly radiusRepo: IRadiusServerProfileRepository,
    @Inject(LDAP_SERVER_PROFILE_REPOSITORY_TOKEN)
    private readonly ldapRepo: ILdapServerProfileRepository,
    @Inject(AUTHENTICATION_PROFILE_REPOSITORY_TOKEN)
    private readonly authRepo: IAuthenticationProfileRepository,
    @Inject(IDENTITY_SETTINGS_REPOSITORY_TOKEN)
    private readonly settingsRepo: IIdentitySettingsRepository,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.seedRadiusIfEmpty();
    await this.seedLdapIfEmpty();
    await this.seedAuthProfilesIfEmpty();
    await this.seedSettingsIfEmpty();
  }

  private async seedRadiusIfEmpty(): Promise<{ id: string } | null> {
    const existing = await this.radiusRepo.findAll();
    if (existing.length > 0) return existing[0] ? { id: (existing[0] as any).getId?.() ?? '' } : null;

    const id = randomUUID();
    const profile = RadiusServerProfile.create(
      id,
      'lab-radius',
      String(this.configService.get('RADIUS_HOST', { infer: true })),
      Port.create(Number(this.configService.get('RADIUS_PORT', { infer: true }))),
      Number(this.configService.get('RADIUS_TIMEOUT_MS', { infer: true })),
      Number(this.configService.get('RADIUS_RETRIES', { infer: true })),
      IpAddress.create(String(this.configService.get('RADIUS_NAS_IP', { infer: true }))),
      String(this.configService.get('RADIUS_NAS_IDENTIFIER', { infer: true })),
      AuthProtocol.create('pap'),
      SecretRef.create(`secret://radius-profiles/${id}/shared-secret`),
      new Date(),
      new Date(),
    );
    await this.radiusRepo.save(profile);
    this.logger.log({ event: 'identity.bootstrap.radius_seeded', id });
    return { id };
  }

  private async seedLdapIfEmpty(): Promise<{ id: string } | null> {
    const existing = await this.ldapRepo.findAll();
    if (existing.length > 0) return null;

    const id = randomUUID();
    const profile = LdapServerProfile.create(
      id,
      'lab-ldap',
      String(this.configService.get('IDENTITY_LDAP_HOST', { infer: true })),
      Port.create(Number(this.configService.get('IDENTITY_LDAP_PORT', { infer: true }))),
      LdapTlsMode.create('none'),
      String(this.configService.get('IDENTITY_LDAP_BIND_DN', { infer: true })),
      SecretRef.create(`secret://ldap-profiles/${id}/bind-password`),
      String(this.configService.get('IDENTITY_LDAP_USER_BASE_DN', { infer: true })),
      String(this.configService.get('IDENTITY_LDAP_USER_FILTER_ATTRIBUTE', { infer: true })),
      String(this.configService.get('IDENTITY_LDAP_GROUP_BASE_DN', { infer: true })),
      String(this.configService.get('IDENTITY_LDAP_GROUP_MEMBER_ATTRIBUTE', { infer: true })),
      String(this.configService.get('IDENTITY_LDAP_GROUP_NAME_ATTRIBUTE', { infer: true })),
      Number(this.configService.get('IDENTITY_LDAP_TIMEOUT_MS', { infer: true })),
      new Date(),
      new Date(),
    );
    await this.ldapRepo.save(profile);
    this.logger.log({ event: 'identity.bootstrap.ldap_seeded', id });
    return { id };
  }

  private async seedAuthProfilesIfEmpty(): Promise<{ portalId: string; adminId: string } | null> {
    const existing = await this.authRepo.findAll();
    if (existing.length > 0) return null;

    const radius = (await this.radiusRepo.findAll())[0];
    if (!radius) return null;

    const portalId = randomUUID();
    const adminId = randomUUID();
    const portal = AuthenticationProfile.create(
      portalId,
      'portal-radius',
      AuthProviderType.create('radius'),
      radius.getId(),
      [],
      IdentityRoleSource.create('radius_vsa'),
      'permissive',
      new Date(), new Date(),
    );
    const admin = AuthenticationProfile.create(
      adminId,
      'admin-local',
      AuthProviderType.create('local'),
      null,
      [],
      IdentityRoleSource.create('local_table'),
      'strict',
      new Date(), new Date(),
    );
    await this.authRepo.save(portal);
    await this.authRepo.save(admin);
    this.logger.log({ event: 'identity.bootstrap.auth_seeded', portalId, adminId });
    return { portalId, adminId };
  }

  private async seedSettingsIfEmpty(): Promise<void> {
    const settings = await this.settingsRepo.load();
    if (settings.getPortalAuthProfileId() && settings.getAdminAuthProfileId()) return;

    const profiles = await this.authRepo.findAll();
    const portal = profiles.find((p) => p.getName() === 'portal-radius');
    const admin = profiles.find((p) => p.getName() === 'admin-local');
    if (!portal || !admin) return;

    settings.setPortalAuthProfileId(portal.getId());
    settings.setAdminAuthProfileId(admin.getId());
    settings.setUpdatedAt(new Date());
    await this.settingsRepo.save(settings);
    this.logger.log({ event: 'identity.bootstrap.settings_seeded' });
  }
}
```

- [ ] **Step 4: Wire DI**

Add `IdentityBootstrapSeedService` to the same module that registered the JSON repos. Mark it as a `provider` (NestJS will run `onModuleInit` automatically).

- [ ] **Step 5: Run, expect PASS**

Run: `cd backend && npm test -- identity-bootstrap-seed.service.spec`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/application/services/identity-bootstrap-seed.service.ts \
        backend/src/application/services/identity-bootstrap-seed.service.spec.ts \
        backend/src/<modules where DI was wired>
git commit -m "feat(identity): seed identity profiles from env on bootstrap"
```

---

## Section 6 — Snapshot payload wiring

### Task 6.1: Extend `ConfigBundlePayload`

**Files:**
- Modify: `backend/src/domain/value-objects/config-snapshot-payload.interface.ts`

- [ ] **Step 1: Edit interface**

Add four new sections; keep existing ones as-is:

```typescript
import { AuthenticationProfile } from '../entities/authentication-profile.entity.js';
import { IdentitySettings } from '../entities/identity-settings.entity.js';
import { LdapServerProfile } from '../entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../entities/radius-server-profile.entity.js';
// ... existing imports ...

export interface ConfigBundlePayload {
  // ... existing fields ...
  radius_server_profiles: { items: RadiusServerProfile[] };
  ldap_server_profiles: { items: LdapServerProfile[] };
  authentication_profiles: { items: AuthenticationProfile[] };
  identity_settings: IdentitySettings;
}
```

- [ ] **Step 2: Type-check**

Run: `cd backend && npx tsc --noEmit`
Expected: many errors about missing identity sections in apply/import/rollback/mapper. This is intentional — Tasks 6.2–6.5 fix them.

- [ ] **Step 3: Do NOT commit yet** — will commit together with the matching mapper changes in Task 6.2.

---

### Task 6.2: Extend `config-payload.mapper.ts`

**Files:**
- Modify: `backend/src/infrastructure/persistence/mappers/config-payload.mapper.ts`

- [ ] **Step 1: Add schema fields**

```typescript
import { AuthenticationProfilesFile } from '../schemas/authentication-profiles.schema.js';
import { IdentitySettingsFile } from '../schemas/identity-settings.schema.js';
import { LdapServerProfilesFile } from '../schemas/ldap-server-profiles.schema.js';
import { RadiusServerProfilesFile } from '../schemas/radius-server-profiles.schema.js';
import { AuthenticationProfileJsonMapper } from './authentication-profile-json.mapper.js';
import { IdentitySettingsJsonMapper } from './identity-settings-json.mapper.js';
import { LdapServerProfileJsonMapper } from './ldap-server-profile-json.mapper.js';
import { RadiusServerProfileJsonMapper } from './radius-server-profile-json.mapper.js';

export interface ConfigBundlePayloadSchema {
  // ... existing fields ...
  radius_server_profiles: RadiusServerProfilesFile;
  ldap_server_profiles: LdapServerProfilesFile;
  authentication_profiles: AuthenticationProfilesFile;
  identity_settings: IdentitySettingsFile;
}
```

- [ ] **Step 2: Update `mapConfigSnapshotToPayloadRecord`**

Add inside the `bundle` literal at the bottom of the function:

```typescript
radius_server_profiles: {
  items: payload.bundle.radius_server_profiles.items.map((p) =>
    RadiusServerProfileJsonMapper.toRecord(p),
  ),
},
ldap_server_profiles: {
  items: payload.bundle.ldap_server_profiles.items.map((p) =>
    LdapServerProfileJsonMapper.toRecord(p),
  ),
},
authentication_profiles: {
  items: payload.bundle.authentication_profiles.items.map((p) =>
    AuthenticationProfileJsonMapper.toRecord(p),
  ),
},
identity_settings: IdentitySettingsJsonMapper.toRecord(
  payload.bundle.identity_settings,
),
```

- [ ] **Step 3: Update `mapConfigBundlePayloadToDomain`**

Mirror change:

```typescript
radius_server_profiles: {
  items: payload.bundle.radius_server_profiles.items.map((p) =>
    RadiusServerProfileJsonMapper.toDomain(p),
  ),
},
ldap_server_profiles: {
  items: payload.bundle.ldap_server_profiles.items.map((p) =>
    LdapServerProfileJsonMapper.toDomain(p),
  ),
},
authentication_profiles: {
  items: payload.bundle.authentication_profiles.items.map((p) =>
    AuthenticationProfileJsonMapper.toDomain(p),
  ),
},
identity_settings: IdentitySettingsJsonMapper.toDomain(
  payload.bundle.identity_settings,
),
```

- [ ] **Step 4: Type-check**

Run: `cd backend && npx tsc --noEmit`
Expected: errors only in `apply-config-snapshot.use-case.ts`, `import-config.use-case.ts`, `rollback-config.use-case.ts`, `grpc-config-snapshot-push.service.ts`. These are fixed in subsequent tasks.

- [ ] **Step 5: Commit (interface + mapper together)**

```bash
git add backend/src/domain/value-objects/config-snapshot-payload.interface.ts \
        backend/src/infrastructure/persistence/mappers/config-payload.mapper.ts
git commit -m "feat(identity): include identity profiles in config snapshot payload"
```

---

### Task 6.3: Update `ApplyConfigSnapshotUseCase`

**Files:**
- Modify: `backend/src/application/use-cases/apply-config-snapshot.use-case.ts`

- [ ] **Step 1: Inject the four new repos in the constructor**

Add to `constructor` in the same style as existing `@Inject(...)` lines:

```typescript
@Inject(RADIUS_SERVER_PROFILE_REPOSITORY_TOKEN)
private readonly radiusServerProfileRepository: IRadiusServerProfileRepository,
@Inject(LDAP_SERVER_PROFILE_REPOSITORY_TOKEN)
private readonly ldapServerProfileRepository: ILdapServerProfileRepository,
@Inject(AUTHENTICATION_PROFILE_REPOSITORY_TOKEN)
private readonly authenticationProfileRepository: IAuthenticationProfileRepository,
@Inject(IDENTITY_SETTINGS_REPOSITORY_TOKEN)
private readonly identitySettingsRepository: IIdentitySettingsRepository,
```

- [ ] **Step 2: Read identity state inside `execute`**

Add to the block of `await` reads at the top of `execute`:

```typescript
const allRadiusProfiles = await this.radiusServerProfileRepository.findAll();
const allLdapProfiles = await this.ldapServerProfileRepository.findAll();
const allAuthProfiles = await this.authenticationProfileRepository.findAll();
const identitySettings = await this.identitySettingsRepository.load();
```

- [ ] **Step 3: Include them in `configSnposhotPayload.bundle`**

```typescript
radius_server_profiles: { items: [...allRadiusProfiles] },
ldap_server_profiles: { items: [...allLdapProfiles] },
authentication_profiles: { items: [...allAuthProfiles] },
identity_settings: identitySettings,
```

- [ ] **Step 4: Add identity counts to the success log**

```typescript
counts: {
  // ... existing counts ...
  radiusServerProfiles: allRadiusProfiles.length,
  ldapServerProfiles: allLdapProfiles.length,
  authenticationProfiles: allAuthProfiles.length,
}
```

- [ ] **Step 5: Type-check + run apply tests**

Run: `cd backend && npx tsc --noEmit && npm test -- apply-config-snapshot`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/application/use-cases/apply-config-snapshot.use-case.ts
git commit -m "feat(identity): include identity profiles in apply-config-snapshot"
```

---

### Task 6.4: Update `ImportConfigUseCase`

**Files:**
- Modify: `backend/src/application/use-cases/import-config.use-case.ts`

- [ ] **Step 1: Inject the four new repos** (same pattern as Task 6.3 Step 1)

- [ ] **Step 2: Map imported records to entities**

After the existing `importedX.map(...)` blocks, add:

```typescript
const importedRadiusProfiles = (payload.bundle.radius_server_profiles?.items ?? []).map(
  (r: any) => RadiusServerProfileJsonMapper.toDomain(r),
);
const importedLdapProfiles = (payload.bundle.ldap_server_profiles?.items ?? []).map(
  (r: any) => LdapServerProfileJsonMapper.toDomain(r),
);
const importedAuthProfiles = (payload.bundle.authentication_profiles?.items ?? []).map(
  (r: any) => AuthenticationProfileJsonMapper.toDomain(r),
);
const importedSettings = payload.bundle.identity_settings
  ? IdentitySettingsJsonMapper.toDomain(payload.bundle.identity_settings as any)
  : IdentitySettings.create(null, null, null, new Date());
```

- [ ] **Step 2a: Validate referential integrity of imported payload**

After mapping, before applying, validate:

```typescript
// Issue A: snapshoty maja round-trippowac, ale nie wolno zaimportowac
// auth profilu wskazujacego nieistniejacy server profile.
const radiusIds = new Set(importedRadiusProfiles.map((p) => p.getId()));
const ldapIds = new Set(importedLdapProfiles.map((p) => p.getId()));
for (const auth of importedAuthProfiles) {
  const refType = auth.getProviderType().getValue;
  const refId = auth.getServerProfileId();
  if (refType === 'radius' && refId && !radiusIds.has(refId)) {
    throw new BadRequestException(
      `Imported authentication profile ${auth.getId()} references missing RADIUS profile ${refId}`,
    );
  }
  if (refType === 'ldap' && refId && !ldapIds.has(refId)) {
    throw new BadRequestException(
      `Imported authentication profile ${auth.getId()} references missing LDAP profile ${refId}`,
    );
  }
}
const authIds = new Set(importedAuthProfiles.map((p) => p.getId()));
for (const ref of [
  ['portal', importedSettings.getPortalAuthProfileId()],
  ['admin', importedSettings.getAdminAuthProfileId()],
  ['vpn', importedSettings.getVpnAuthProfileId()],
] as const) {
  if (ref[1] && !authIds.has(ref[1])) {
    throw new BadRequestException(
      `Imported identity_settings.${ref[0]}AuthProfileId references missing authentication profile ${ref[1]}`,
    );
  }
}
```

- [ ] **Step 3: Add to `domainPayload.bundle`**

```typescript
radius_server_profiles: { items: importedRadiusProfiles },
ldap_server_profiles: { items: importedLdapProfiles },
authentication_profiles: { items: importedAuthProfiles },
identity_settings: importedSettings,
```

- [ ] **Step 4: Apply to repos when active**

Inside the `if (dto.snapshotData.isActive)` block, after existing `overwriteAll` calls:

```typescript
await this.radiusServerProfileRepository.overwriteAll(importedRadiusProfiles);
await this.ldapServerProfileRepository.overwriteAll(importedLdapProfiles);
await this.authenticationProfileRepository.overwriteAll(importedAuthProfiles);
await this.identitySettingsRepository.save(importedSettings);
```

- [ ] **Step 5: Type-check + run import tests**

Run: `cd backend && npx tsc --noEmit && npm test -- import-config`
Expected: PASS (write a new test case asserting that an import with mismatched ref throws `BadRequestException`).

- [ ] **Step 6: Commit**

```bash
git add backend/src/application/use-cases/import-config.use-case.ts
git commit -m "feat(identity): import/apply identity profiles via snapshot"
```

---

### Task 6.5: Update `RollbackConfigUseCase`

**Files:**
- Modify: `backend/src/application/use-cases/rollback-config.use-case.ts`

- [ ] **Step 1: Inject the four new repos**

- [ ] **Step 2: After existing `overwriteAll` calls inside `execute`, add**

```typescript
await this.radiusServerProfileRepository.overwriteAll(
  configBundle.bundle.radius_server_profiles.items,
);
await this.ldapServerProfileRepository.overwriteAll(
  configBundle.bundle.ldap_server_profiles.items,
);
await this.authenticationProfileRepository.overwriteAll(
  configBundle.bundle.authentication_profiles.items,
);
await this.identitySettingsRepository.save(
  configBundle.bundle.identity_settings,
);
```

- [ ] **Step 3: Add identity counts to the success log**

(same shape as in Task 6.3 Step 4).

- [ ] **Step 4: Type-check + run rollback tests**

Run: `cd backend && npx tsc --noEmit && npm test -- rollback-config`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/src/application/use-cases/rollback-config.use-case.ts
git commit -m "feat(identity): rollback identity profiles via snapshot"
```

---

## Section 7 — Proto changes

### Task 7.1: Extend `proto/config/config_models.proto`

**Files:**
- Modify: `proto/config/config_models.proto`

- [ ] **Step 1: Add new messages above `// ── ConfigSectionVersions —`**

Place this block before the `ConfigSectionVersions` section:

```proto
// ── Identity provider profiles (Issue A) ─────────────────────────────────────

// Opaque secret reference. Plaintext nigdy nie wchodzi do snapshotu.
message SecretRef {
  string value = 1; // np. secret://radius-profiles/<uuid>/shared-secret
}

enum AuthProtocol {
  AUTH_PROTOCOL_UNSPECIFIED = 0;
  AUTH_PROTOCOL_PAP         = 1;
  AUTH_PROTOCOL_CHAP        = 2;
  AUTH_PROTOCOL_MSCHAPV2    = 3;
}

enum LdapTlsMode {
  LDAP_TLS_MODE_UNSPECIFIED = 0;
  LDAP_TLS_MODE_NONE        = 1;
  LDAP_TLS_MODE_STARTTLS    = 2;
  LDAP_TLS_MODE_LDAPS       = 3;
}

enum AuthProviderType {
  AUTH_PROVIDER_TYPE_UNSPECIFIED = 0;
  AUTH_PROVIDER_TYPE_RADIUS      = 1;
  AUTH_PROVIDER_TYPE_LDAP        = 2;
  AUTH_PROVIDER_TYPE_LOCAL       = 3;
}

enum IdentityRoleSource {
  IDENTITY_ROLE_SOURCE_UNSPECIFIED = 0;
  IDENTITY_ROLE_SOURCE_LDAP        = 1;
  IDENTITY_ROLE_SOURCE_RADIUS_VSA  = 2;
  IDENTITY_ROLE_SOURCE_LOCAL_TABLE = 3;
}

enum RoleMappingMode {
  ROLE_MAPPING_MODE_UNSPECIFIED = 0;
  ROLE_MAPPING_MODE_STRICT      = 1;
  ROLE_MAPPING_MODE_PERMISSIVE  = 2;
}

message RadiusServerProfile {
  string                    id              = 1;
  string                    name            = 2;
  string                    host            = 3;
  uint32                    port            = 4;
  uint32                    timeout_ms      = 5;
  uint32                    retries         = 6;
  string                    nas_ip          = 7;  // pusty string == null
  string                    nas_identifier  = 8;
  AuthProtocol              auth_protocol   = 9;
  SecretRef                 shared_secret_ref = 10;
  google.protobuf.Timestamp created_at      = 11;
  google.protobuf.Timestamp updated_at      = 12;
}

message LdapServerProfile {
  string                    id                       = 1;
  string                    name                     = 2;
  string                    host                     = 3;
  uint32                    port                     = 4;
  LdapTlsMode               tls_mode                 = 5;
  string                    bind_dn                  = 6;
  SecretRef                 bind_password_ref        = 7;
  string                    user_base_dn             = 8;
  string                    user_filter_attribute    = 9;
  string                    group_base_dn            = 10;
  string                    group_member_attribute   = 11;
  string                    group_name_attribute     = 12;
  uint32                    timeout_ms               = 13;
  google.protobuf.Timestamp created_at               = 14;
  google.protobuf.Timestamp updated_at               = 15;
}

message AuthenticationProfile {
  string                    id                  = 1;
  string                    name                = 2;
  AuthProviderType          provider_type       = 3;
  string                    server_profile_id   = 4; // pusty string == null (lokalny provider)
  repeated string           allow_list          = 5;
  IdentityRoleSource        group_source        = 6;
  RoleMappingMode           role_mapping_mode   = 7;
  google.protobuf.Timestamp created_at          = 8;
  google.protobuf.Timestamp updated_at          = 9;
}

message IdentitySettings {
  string                    portal_auth_profile_id = 1; // pusty string == null
  string                    admin_auth_profile_id  = 2;
  string                    vpn_auth_profile_id    = 3;
  google.protobuf.Timestamp updated_at             = 4;
}

message IdentityConfig {
  repeated RadiusServerProfile   radius_server_profiles   = 1;
  repeated LdapServerProfile     ldap_server_profiles     = 2;
  repeated AuthenticationProfile authentication_profiles  = 3;
  IdentitySettings               identity_settings        = 4;
}
```

- [ ] **Step 2: Bump section version field in `ConfigSectionVersions`**

Add:

```proto
  uint64 identity_config = 12;
```

(Append at the end so existing field numbers stay stable.)

- [ ] **Step 3: Regenerate proto bindings**

Run the project's proto generation script:

```bash
cd backend && npm run proto:gen
```

If the script name differs, locate it via `cat package.json | grep proto`.

Expected: `backend/src/infrastructure/grpc/generated/config/config_models.{ts,js}` updated.

- [ ] **Step 4: Commit**

```bash
git add proto/config/config_models.proto \
        backend/src/infrastructure/grpc/generated/
git commit -m "feat(identity): add identity config proto messages"
```

---

### Task 7.2: Extend `proto/services/config_snapshot_service.proto`

**Files:**
- Modify: `proto/services/config_snapshot_service.proto`

- [ ] **Step 1: Add new field to `ConfigBundle`**

```proto
  message ConfigBundle {
    // ... existing fields up to 12 ...
    raptorgate.config.IdentityConfig identity_config = 13;
  }
```

- [ ] **Step 2: Regenerate**

```bash
cd backend && npm run proto:gen
```

- [ ] **Step 3: Commit**

```bash
git add proto/services/config_snapshot_service.proto \
        backend/src/infrastructure/grpc/generated/
git commit -m "feat(identity): include identity_config in ConfigBundle proto"
```

---

### Task 7.3: Extend `GrpcConfigSnapshotPushService.toBundle`

**Files:**
- Modify: `backend/src/infrastructure/adapters/grpc-config-snapshot-push.service.ts`

- [ ] **Step 1: Locate `toBundle(payload: ConfigSnapshotPayload)` and add identity config**

Add after the existing `tlsInspectionPolicy` mapping. Pseudo (adapt to actual existing function shape):

```typescript
const identityConfig = {
  radiusServerProfiles: payload.bundle.radius_server_profiles.items.map((p) => ({
    id: p.getId(),
    name: p.getName(),
    host: p.getHost(),
    port: p.getPort().getValue,
    timeoutMs: p.getTimeoutMs(),
    retries: p.getRetries(),
    nasIp: p.getNasIp()?.getValue ?? '',
    nasIdentifier: p.getNasIdentifier(),
    authProtocol: protoAuthProtocol(p.getAuthProtocol().getValue),
    sharedSecretRef: { value: p.getSharedSecretRef().getValue },
    createdAt: this.toTimestamp(p.getCreatedAt()),
    updatedAt: this.toTimestamp(p.getUpdatedAt()),
  })),
  ldapServerProfiles: payload.bundle.ldap_server_profiles.items.map((p) => ({
    id: p.getId(),
    name: p.getName(),
    host: p.getHost(),
    port: p.getPort().getValue,
    tlsMode: protoLdapTlsMode(p.getTlsMode().getValue),
    bindDn: p.getBindDn(),
    bindPasswordRef: { value: p.getBindPasswordRef().getValue },
    userBaseDn: p.getUserBaseDn(),
    userFilterAttribute: p.getUserFilterAttribute(),
    groupBaseDn: p.getGroupBaseDn(),
    groupMemberAttribute: p.getGroupMemberAttribute(),
    groupNameAttribute: p.getGroupNameAttribute(),
    timeoutMs: p.getTimeoutMs(),
    createdAt: this.toTimestamp(p.getCreatedAt()),
    updatedAt: this.toTimestamp(p.getUpdatedAt()),
  })),
  authenticationProfiles: payload.bundle.authentication_profiles.items.map((p) => ({
    id: p.getId(),
    name: p.getName(),
    providerType: protoProviderType(p.getProviderType().getValue),
    serverProfileId: p.getServerProfileId() ?? '',
    allowList: p.getAllowList(),
    groupSource: protoGroupSource(p.getGroupSource().getValue),
    roleMappingMode: protoRoleMappingMode(p.getRoleMappingMode()),
    createdAt: this.toTimestamp(p.getCreatedAt()),
    updatedAt: this.toTimestamp(p.getUpdatedAt()),
  })),
  identitySettings: {
    portalAuthProfileId: payload.bundle.identity_settings.getPortalAuthProfileId() ?? '',
    adminAuthProfileId: payload.bundle.identity_settings.getAdminAuthProfileId() ?? '',
    vpnAuthProfileId: payload.bundle.identity_settings.getVpnAuthProfileId() ?? '',
    updatedAt: this.toTimestamp(payload.bundle.identity_settings.getUpdatedAt()),
  },
};

return {
  // ... existing bundle fields ...
  identityConfig,
};
```

- [ ] **Step 2: Add proto enum mapping helpers**

In the same file, near the other mappers (or in a private static helper section), add:

```typescript
import {
  AuthProtocol as ProtoAuthProtocol,
  AuthProviderType as ProtoAuthProviderType,
  IdentityRoleSource as ProtoIdentityRoleSource,
  LdapTlsMode as ProtoLdapTlsMode,
  RoleMappingMode as ProtoRoleMappingMode,
} from '../grpc/generated/config/config_models.js';

function protoAuthProtocol(v: string): ProtoAuthProtocol {
  switch (v) {
    case 'pap': return ProtoAuthProtocol.AUTH_PROTOCOL_PAP;
    case 'chap': return ProtoAuthProtocol.AUTH_PROTOCOL_CHAP;
    case 'mschapv2': return ProtoAuthProtocol.AUTH_PROTOCOL_MSCHAPV2;
    default: return ProtoAuthProtocol.AUTH_PROTOCOL_UNSPECIFIED;
  }
}
function protoLdapTlsMode(v: string): ProtoLdapTlsMode {
  switch (v) {
    case 'none': return ProtoLdapTlsMode.LDAP_TLS_MODE_NONE;
    case 'starttls': return ProtoLdapTlsMode.LDAP_TLS_MODE_STARTTLS;
    case 'ldaps': return ProtoLdapTlsMode.LDAP_TLS_MODE_LDAPS;
    default: return ProtoLdapTlsMode.LDAP_TLS_MODE_UNSPECIFIED;
  }
}
function protoProviderType(v: string): ProtoAuthProviderType {
  switch (v) {
    case 'radius': return ProtoAuthProviderType.AUTH_PROVIDER_TYPE_RADIUS;
    case 'ldap': return ProtoAuthProviderType.AUTH_PROVIDER_TYPE_LDAP;
    case 'local': return ProtoAuthProviderType.AUTH_PROVIDER_TYPE_LOCAL;
    default: return ProtoAuthProviderType.AUTH_PROVIDER_TYPE_UNSPECIFIED;
  }
}
function protoGroupSource(v: string): ProtoIdentityRoleSource {
  switch (v) {
    case 'ldap': return ProtoIdentityRoleSource.IDENTITY_ROLE_SOURCE_LDAP;
    case 'radius_vsa': return ProtoIdentityRoleSource.IDENTITY_ROLE_SOURCE_RADIUS_VSA;
    case 'local_table': return ProtoIdentityRoleSource.IDENTITY_ROLE_SOURCE_LOCAL_TABLE;
    default: return ProtoIdentityRoleSource.IDENTITY_ROLE_SOURCE_UNSPECIFIED;
  }
}
function protoRoleMappingMode(v: 'strict' | 'permissive'): ProtoRoleMappingMode {
  switch (v) {
    case 'strict': return ProtoRoleMappingMode.ROLE_MAPPING_MODE_STRICT;
    case 'permissive': return ProtoRoleMappingMode.ROLE_MAPPING_MODE_PERMISSIVE;
  }
}
```

- [ ] **Step 3: Update `bundleCounts(payload)` helper to include identity counts**

```typescript
function bundleCounts(payload: ConfigSnapshotPayload) {
  return {
    // ... existing counts ...
    radiusServerProfiles: payload.bundle.radius_server_profiles.items.length,
    ldapServerProfiles: payload.bundle.ldap_server_profiles.items.length,
    authenticationProfiles: payload.bundle.authentication_profiles.items.length,
  };
}
```

- [ ] **Step 4: Type-check + run all backend tests**

Run: `cd backend && npx tsc --noEmit && npm test`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add backend/src/infrastructure/adapters/grpc-config-snapshot-push.service.ts
git commit -m "feat(identity): push identity_config to firewall via gRPC"
```

---

## Section 8 — Integration verification

### Task 8.1: End-to-end snapshot round-trip test

**Goal:** Prove that `apply → export → import → rollback` preserves identity config.

**Files:**
- Create: `backend/test/integration/identity-snapshot-round-trip.spec.ts`

- [ ] **Step 1: Write the failing integration test**

```typescript
// backend/test/integration/identity-snapshot-round-trip.spec.ts
import { Test } from '@nestjs/testing';
import { hash } from 'node:crypto';
import { ApplyConfigSnapshotUseCase } from '../../src/application/use-cases/apply-config-snapshot.use-case.js';
import { ExportConfigUseCase } from '../../src/application/use-cases/export-config.use-case.js';
import { ImportConfigUseCase } from '../../src/application/use-cases/import-config.use-case.js';
import { RollbackConfigUseCase } from '../../src/application/use-cases/rollback-config.use-case.js';
// ... import the same module imports the existing apply spec uses ...

// Skel: adopt existing integration test pattern in repo (see e.g.
// `create-rule.use-case.integration.spec.ts`).
describe('Identity snapshot round-trip', () => {
  it('apply -> export -> import preserves radius/ldap/auth profiles + settings', async () => {
    // 1. seed a RADIUS profile, an LDAP profile, two auth profiles, set identity_settings.
    // 2. call apply, expect snapshot contains 4 sections.
    // 3. call export, decode payload, assert identity sections present and equal.
    // 4. call import with payload, expect repos overwritten with the same content.
  });

  it('rollback restores identity profiles from a prior snapshot', async () => {
    // 1. seed profiles A, apply -> snapshot S1.
    // 2. mutate to profiles B, apply -> snapshot S2.
    // 3. rollback to S1, assert repos contain A.
  });
});
```

- [ ] **Step 2: Implement test using the repo's existing integration test scaffolding**

Mirror `create-rule.use-case.integration.spec.ts`. Use real `JsonXRepository` against a tmp `data/` dir (see how the existing test sets `process.cwd()` or the file paths). Stub the `IConfigSnapshotPushService` so no real gRPC call happens.

- [ ] **Step 3: Run, expect PASS**

Run: `cd backend && npm test -- identity-snapshot-round-trip`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add backend/test/integration/identity-snapshot-round-trip.spec.ts
git commit -m "test(identity): snapshot round-trip preserves identity config"
```

---

## Section 9 — Final verification

### Task 9.1: Full build + tests

- [ ] **Step 1: Backend build + tests**

Run: `cd backend && npx tsc --noEmit && npm test`
Expected: green.

- [ ] **Step 2: Rust build (proto regeneration may have changed bindings)**

Run: `cargo build --workspace`
Expected: green. If the firewall's generated proto code now contains unread `identity_config`, that is fine for Issue A — it will be consumed in Issues D/E/G.

- [ ] **Step 3: Lint**

Run: `cd backend && npm run lint`
Expected: green.

- [ ] **Step 4: Smoke-test bootstrap**

```bash
cd backend
rm -f data/json-db/radius_server_profiles.json \
      data/json-db/ldap_server_profiles.json \
      data/json-db/authentication_profiles.json \
      data/json-db/identity_settings.json
npm run start:dev &
sleep 5
test -s data/json-db/radius_server_profiles.json
test -s data/json-db/ldap_server_profiles.json
test -s data/json-db/authentication_profiles.json
test -s data/json-db/identity_settings.json
kill %1
```

Expected: all four files now exist and contain seeded entries.

- [ ] **Step 5: REST sanity check from r1 (optional but recommended)**

Per memory `project_backend_visibility.md`, the backend listens only on r1 inside the lab. From `vagrant ssh r1` invoke an apply request, then export, and inspect the returned `payloadJson.bundle` — it must include `radius_server_profiles`, `ldap_server_profiles`, `authentication_profiles`, `identity_settings`.

- [ ] **Step 6: Commit any incidental fixes**

If lint or smoke surfaces issues, fix and commit a single follow-up commit before declaring done.

---

## Acceptance criteria recap (mirrors Issue A spec)

- [ ] RADIUS, LDAP, authentication profiles, and identity settings are first-class entities with their own JSON files.
- [ ] All four are part of `ConfigBundlePayload` and round-trip through apply/import/export/rollback.
- [ ] Runtime sessions remain out of the snapshot (already the case; verified by inspecting `IdentitySession` is not added to the bundle in any task).
- [ ] Cannot delete a server profile referenced by an authentication profile (`IdentityReferentialIntegrityService.assertRadius/LdapProfileDeletable`).
- [ ] Cannot delete an authentication profile referenced by `IdentitySettings` (`assertAuthenticationProfileDeletable`).
- [ ] Env stays only as bootstrap default seed; the `IdentityBootstrapSeedService` only writes when the JSON store is empty.
- [ ] Plaintext secrets never enter the snapshot — only `SecretRef` strings. (Resolution and storage of the actual values is Issue B's deliverable.)
- [ ] Proto `config_models.proto` and `config_snapshot_service.proto` carry the new identity config; backend pushes it to the firewall.

---

## Self-review notes

- **Type consistency:** All getters use the existing pattern: getter `getValue` for VOs (Port, IpAddress style), method `getX()` for entity fields. Mappers consistently call `.getValue` (not `.getValue()`) on VOs that follow Port-style getters; for AuthProtocol/LdapTlsMode/etc. I declared `public get getValue()` to match. Watch for mistakes between `getValue` (getter) vs `getValue()` (method).
- **Singleton storage:** `IdentitySettings` is intentionally not a list. `JsonIdentitySettingsRepository` writes one object, not `{ items: [...] }`.
- **`overwriteAll` for settings:** there is no list, so `IIdentitySettingsRepository` exposes `save()` not `overwriteAll()`. Apply/import/rollback use `save()` accordingly.
- **`SecretRef` and Issue B:** This plan stores only the reference string, never plaintext. If reviewer asks "where do secrets go?" — that is Issue B. The contract here is fixed: `secret://<scope>/<owner-id>/<field>`.
- **Existing Rust code:** The Rust crate currently does not consume `identity_config`. That is expected — Issues D/E/G adapt the firewall side. For Issue A, only the backend → firewall transport contract has to be ready.

