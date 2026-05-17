# RADIUS PAP Semantic Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor existing PAP RADIUS authentication so RaptorGate separates provider authentication, Authentication Profile authorization, Palo Alto RADIUS VSA semantics, administrator authorization, lockout, and User-ID group sources in the same way an administrator expects from PAN-OS.

**Architecture:** Keep the existing backend/firewall split. Backend continues to speak RADIUS over UDP/PAP and owns identity configuration, canonical usernames, lockout state, Authentication Profile decisions, admin role decisions, User-ID group resolution, compatibility diagnostics, and runtime replay. Firewall receives richer User-ID mapping metadata over the existing identity gRPC service and evaluates `identity_group` only from User-ID mapping groups, with migrated compatibility marked separately.

**Tech Stack:** TypeScript / NestJS / Zod / Jest / protobuf3 / ts-proto / Rust 2024 / tonic / prost / Cargo.

---

## Scope

### In Scope

- PAP-compatible RADIUS flow remains interoperable with the current UDP client.
- Palo Alto Vendor-Specific Attributes are parsed into typed fields:
  - `PaloAlto-Admin-Role`
  - `PaloAlto-Admin-Access-Domain`
  - `PaloAlto-Panorama-Admin-Role`
  - `PaloAlto-Panorama-Admin-Access-Domain`
  - `PaloAlto-User-Group`
  - endpoint/client metadata fields retained for diagnostics.
- `AuthenticationFlowKind` replaces the current `'portal' | 'admin'` flow shape:
  - `admin_login`
  - `portal_login`
  - `auth_policy_portal`
  - `api_login`
- `api_login` remains local/API only. External RADIUS for `api_login` is not enabled by this plan.
- Canonical identity is produced before lockout, provider auth, Allow List, admin authorization, and User-ID mapping.
- Authentication Profile gets `allowedFlows`, `retrieveUserGroupFromRadius`, `allowList`, failed-attempt lockout settings, `requireGroupMappingForUserId`, and migration-only `radiusVsaAsPolicyGroupsCompatibility`.
- A durable JSON-backed `AuthenticationLockoutStore` is added for failed attempts and active lockouts.
- Authentication Profile evaluation becomes a state machine:
  - `locked_out`
  - `provider_rejected`
  - `provider_unavailable`
  - `provider_protocol_error`
  - `accepted_but_not_allowed`
  - `authorized`
- RADIUS `Access-Accept` does not create sessions until the profile evaluator authorizes the identity.
- Admin login order becomes:
  - provider accept
  - Authentication Profile authorization
  - typed admin VSA or explicit fallback mapping authorization
  - admin session creation.
- RADIUS `PaloAlto-User-Group` is used only for Authentication Profile Allow List when `retrieveUserGroupFromRadius` is enabled.
- Security Policy `identity_group` is sourced from User-ID group mapping, not from normal RADIUS VSA groups.
- Migrated compatibility can preserve old RADIUS-VSA-as-policy-group behavior only through `radiusVsaAsPolicyGroupsCompatibility`, `groupSource='radius_compat'`, diagnostics, and audit event `auth.compat.radius_vsa_policy_group.used`.
- Runtime identity sync adds `group_source` and `group_mapping_status`.
- Frontend/API DTOs expose new Authentication Profile fields.

### Out Of Scope

- PEAP-MSCHAPv2.
- PEAP-GTC.
- EAP-TTLS/PAP.
- CHAP.
- Full Authentication Policy packet-path rulebase.
- Full Authentication Portal rebuild.
- MFA.
- External RADIUS authentication for `api_login`.

## Semantic Contracts

### Canonical Identity

```ts
export interface CanonicalIdentity {
  original: string;
  loginName: string;
  normalizedUser: string;
  domain: string | null;
  displayName: string;
}
```

Rules:

- Trim leading and trailing whitespace.
- Empty value is rejected.
- `DOMAIN\user` uses the first backslash as separator; values with another backslash in the user part are rejected as ambiguous.
- `user@domain` uses the first `@` as separator; values with another `@` are rejected as ambiguous.
- `domain\user@realm` is rejected as ambiguous.
- Bare `user` has `domain=null`.
- `normalizedUser` and `domain` are lower-case.
- `displayName` is `domain\normalizedUser` when domain exists, otherwise `normalizedUser`.
- `loginName` is the trimmed original value until a profile username modifier is introduced in a separate plan.

### Authentication Profile Allow List

```ts
export type AuthenticationProfileAllowListEntry =
  | { kind: 'all' }
  | { kind: 'user'; value: string }
  | { kind: 'group'; value: string };
```

Rules:

- Empty Allow List denies non-local authentication.
- `all` allows any provider-accepted identity.
- `user` matches canonical normalized user and domain display name.
- `group` matches LDAP group mapping for LDAP-backed profiles.
- `group` matches RADIUS `PaloAlto-User-Group` only when `retrieveUserGroupFromRadius=true`.

### Runtime Group Metadata

```ts
export type UserIdGroupSource = 'ldap' | 'local' | 'radius_compat' | 'none';

export type UserIdGroupMappingStatus =
  | 'resolved'
  | 'unavailable'
  | 'disabled'
  | 'required_but_failed';
```

Rules:

- LDAP unavailable after successful RADIUS end-user authentication creates `groups=[]`, `groupSource='ldap'`, `groupMappingStatus='unavailable'` unless `requireGroupMappingForUserId=true`.
- `requireGroupMappingForUserId=true` turns LDAP group lookup failure into authorization denial and creates no User-ID mapping.
- Normal RADIUS `PaloAlto-User-Group` never becomes `identity_group`.
- Migration-only compatibility may create `groupSource='radius_compat'`, `groupMappingStatus='resolved'`.

---

## File Structure

### New Backend Files

- `backend/src/application/services/authentication-identity-normalizer.service.ts` — canonical username parser.
- `backend/src/application/services/authentication-identity-normalizer.service.spec.ts`
- `backend/src/application/ports/authentication-lockout-store.interface.ts` — lockout persistence port.
- `backend/src/infrastructure/persistence/schemas/authentication-lockouts.schema.ts`
- `backend/src/infrastructure/persistence/repositories/json-authentication-lockout.store.ts`
- `backend/src/infrastructure/persistence/repositories/json-authentication-lockout.store.spec.ts`
- `backend/src/application/services/authentication-profile-evaluator.service.ts` — state machine for profile gates and lockout.
- `backend/src/application/services/authentication-profile-evaluator.service.spec.ts`
- `backend/src/application/services/authentication-group-resolver.service.spec.ts`

### Modified Backend Files

- `backend/src/infrastructure/adapters/radius/radius-packet.ts`
- `backend/src/infrastructure/adapters/radius/radius-packet.spec.ts`
- `backend/src/application/ports/radius-authenticator.interface.ts`
- `backend/src/infrastructure/adapters/udp-radius-authenticator.ts`
- `backend/src/application/dtos/authentication-engine.dto.ts`
- `backend/src/application/services/authentication-engine.service.ts`
- `backend/src/application/services/authentication-engine.service.spec.ts`
- `backend/src/application/services/authentication-profile-resolver.service.ts`
- `backend/src/application/services/radius-authentication-provider.service.ts`
- `backend/src/application/services/radius-authentication-provider.service.spec.ts`
- `backend/src/application/services/authentication-group-resolver.service.ts`
- `backend/src/application/services/authentication-group-resolver.service.spec.ts`
- `backend/src/application/services/admin-authorization.service.ts`
- `backend/src/application/services/admin-authorization.service.spec.ts`
- `backend/src/application/use-cases/authenticate-identity.use-case.ts`
- `backend/src/application/use-cases/authenticate-identity.use-case.spec.ts`
- `backend/src/application/use-cases/login-user.use-case.ts`
- `backend/src/application/use-cases/login-user.use-case.spec.ts`
- `backend/src/application/ports/identity-session-sync-service.interface.ts`
- `backend/src/infrastructure/adapters/grpc-identity-session-sync.service.ts`
- `backend/src/infrastructure/identity/identity-group-refresher.service.ts`
- `backend/src/infrastructure/identity/identity-session-replay.service.ts`
- `backend/src/domain/entities/identity-authentication-profile.entity.ts`
- `backend/src/domain/entities/identity-authentication-profile.entity.spec.ts`
- `backend/src/domain/entities/identity-session.entity.ts`
- `backend/src/domain/entities/identity-session.entity.spec.ts`
- `backend/src/infrastructure/persistence/schemas/identity-config.schema.ts`
- `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts`
- `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.spec.ts`
- `backend/src/infrastructure/persistence/schemas/identity-sessions.schema.ts`
- `backend/src/infrastructure/persistence/mappers/identity-session-json.mapper.ts`
- `backend/src/infrastructure/persistence/repositories/json-identity-session.store.spec.ts`
- `backend/src/presentation/dtos/identity-config-profile.dto.ts`
- `backend/src/presentation/dtos/identity-config-profile-response.dto.ts`
- `backend/src/presentation/mappers/identity-config-response.mapper.ts`
- `backend/src/application/use-cases/create-authentication-profile.use-case.ts`
- `backend/src/application/use-cases/create-authentication-profile.use-case.spec.ts`
- `backend/src/application/use-cases/update-authentication-profile.use-case.ts`
- `backend/src/application/use-cases/update-authentication-profile.use-case.spec.ts`
- `backend/src/modules/authentication-engine.module.ts`
- `backend/src/modules/identity.module.ts`
- `frontend/src/types/identity/IdentityConfig.ts`
- `frontend/src/services/identityConfig.ts`

### Modified Proto And Firewall Files

- `proto/services/identity_session_service.proto`
- `backend/src/infrastructure/grpc/generated/services/identity_session_service.ts` — generated by `cd backend && npm run proto:generate`.
- `crates/raptorgate/src/identity/session.rs`
- `crates/raptorgate/src/identity/store.rs`
- `crates/raptorgate/src/identity/service.rs`
- `crates/raptorgate/src/policy/policy_evaluator.rs`
- `crates/raptorgate/tests/test_query_server.rs`

### Runtime Data Files

- `backend/data/json-db/authentication_lockouts.json` — created on first lockout read/write with `{ "items": [] }`.
- Existing `backend/data/json-db/identity-config.json` gains new fields through schema defaults and rewrite on next save.
- Existing `backend/data/json-db/identity_sessions.json` gains `groupSource` and `groupMappingStatus` through schema defaults and rewrite on next session save.

---

## Task 1: Typed Palo Alto RADIUS Attributes

**Files:**
- Modify: `backend/src/application/ports/radius-authenticator.interface.ts`
- Modify: `backend/src/infrastructure/adapters/radius/radius-packet.ts`
- Test: `backend/src/infrastructure/adapters/radius/radius-packet.spec.ts`
- Modify: `backend/src/infrastructure/adapters/udp-radius-authenticator.ts`

- [ ] **Step 1: Write failing parser tests**

Add tests that prove admin role and user group are not flattened together:

```ts
it('parses Palo Alto VSAs into typed fields', () => {
  const paloAlto = Buffer.concat([
    vsa(25461, [
      vendorSubAttr(1, 'superuser'),
      vendorSubAttr(2, 'vsys-admins'),
      vendorSubAttr(3, 'panorama-superuser'),
      vendorSubAttr(4, 'panorama-domain'),
      vendorSubAttr(5, 'Domain Admins'),
      vendorSubAttr(5, 'VPN Users'),
    ]),
  ]);
  const attrs = attr(RADIUS_ATTR_VENDOR_SPECIFIC, paloAlto);

  const parsed = extractRadiusAttributes(attrs);

  expect(parsed.paloAlto).toEqual({
    adminRole: 'superuser',
    adminAccessDomain: 'vsys-admins',
    panoramaAdminRole: 'panorama-superuser',
    panoramaAdminAccessDomain: 'panorama-domain',
    userGroups: ['Domain Admins', 'VPN Users'],
    userDomain: null,
    clientSourceIp: null,
    clientOs: null,
    clientHostname: null,
    globalProtectClientVersion: null,
  });
  expect(parsed.generic.groups).toEqual([]);
});

it('keeps Filter-Id and Cisco roles as generic diagnostic groups only', () => {
  const cisco = Buffer.concat([
    Buffer.from([0, 0, 0, 9]),
    attr(1, 'shell:roles="admins guests"'),
  ]);
  const attrs = Buffer.concat([
    attr(RADIUS_ATTR_FILTER_ID, 'filter-users'),
    attr(RADIUS_ATTR_VENDOR_SPECIFIC, cisco),
  ]);

  const parsed = extractRadiusAttributes(attrs);

  expect(parsed.generic.groups).toEqual(['filter-users', 'admins', 'guests']);
  expect(parsed.paloAlto.userGroups).toEqual([]);
  expect(parsed.paloAlto.adminRole).toBeNull();
});
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `cd backend && npm test -- radius-packet.spec`

Expected: FAIL with `extractRadiusAttributes` missing.

- [ ] **Step 3: Add typed RADIUS result contracts**

In `backend/src/application/ports/radius-authenticator.interface.ts`, replace the accept result with:

```ts
export interface PaloAltoRadiusAttributes {
  adminRole: string | null;
  adminAccessDomain: string | null;
  panoramaAdminRole: string | null;
  panoramaAdminAccessDomain: string | null;
  userGroups: string[];
  userDomain: string | null;
  clientSourceIp: string | null;
  clientOs: string | null;
  clientHostname: string | null;
  globalProtectClientVersion: string | null;
}

export interface RadiusGenericAttributes {
  groups: string[];
}

export interface RadiusParsedAttributes {
  generic: RadiusGenericAttributes;
  paloAlto: PaloAltoRadiusAttributes;
}

export type RadiusAuthResult =
  | { kind: 'accept'; attributes: RadiusParsedAttributes }
  | { kind: 'reject'; reason: string }
  | { kind: 'timeout' }
  | { kind: 'error'; message: string };
```

- [ ] **Step 4: Implement typed parser**

In `backend/src/infrastructure/adapters/radius/radius-packet.ts`, export `extractRadiusAttributes(attributes: Buffer): RadiusParsedAttributes`. Keep `Filter-Id`, `Class`, and Cisco AVPair in `generic.groups`. Put only vendor 25461 type `5` into `paloAlto.userGroups`; type `1` goes to `adminRole`, type `2` to `adminAccessDomain`, type `3` to `panoramaAdminRole`, type `4` to `panoramaAdminAccessDomain`.

```ts
export function extractRadiusAttributes(attributes: Buffer): RadiusParsedAttributes {
  const values = decodeAttributes(attributes);
  const genericGroups = [
    ...(values.get(RADIUS_ATTR_FILTER_ID) ?? []),
    ...(values.get(RADIUS_ATTR_CLASS) ?? []),
    ...extractCiscoAvPairs(values.get(RADIUS_ATTR_VENDOR_SPECIFIC) ?? []),
  ];

  return {
    generic: { groups: dedupStrings(genericGroups.flatMap((raw) => splitGroupValue(raw.toString('utf8')))) },
    paloAlto: extractPaloAltoAttributes(values.get(RADIUS_ATTR_VENDOR_SPECIFIC) ?? []),
  };
}
```

- [ ] **Step 5: Update UDP authenticator accept path**

In `UdpRadiusAuthenticator.sendOnce`, change accept from:

```ts
settle({
  kind: 'accept',
  groups: extractGroupsFromAttributes(parsed.attributesRaw),
});
```

to:

```ts
settle({
  kind: 'accept',
  attributes: extractRadiusAttributes(parsed.attributesRaw),
});
```

- [ ] **Step 6: Run parser tests**

Run: `cd backend && npm test -- radius-packet.spec`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src/application/ports/radius-authenticator.interface.ts backend/src/infrastructure/adapters/radius/radius-packet.ts backend/src/infrastructure/adapters/radius/radius-packet.spec.ts backend/src/infrastructure/adapters/udp-radius-authenticator.ts
git commit -m "feat(identity): parse typed Palo Alto RADIUS attributes"
```

---

## Task 2: Canonical Identity And Flow Kinds

**Files:**
- Create: `backend/src/application/services/authentication-identity-normalizer.service.ts`
- Test: `backend/src/application/services/authentication-identity-normalizer.service.spec.ts`
- Modify: `backend/src/application/dtos/authentication-engine.dto.ts`
- Modify: `backend/src/application/use-cases/authenticate-identity.use-case.ts`
- Modify: `backend/src/application/use-cases/login-user.use-case.ts`
- Modify: `backend/src/application/services/authentication-profile-resolver.service.ts`
- Test: `backend/src/application/services/authentication-engine.service.spec.ts`

- [ ] **Step 1: Write failing normalizer tests**

```ts
describe('AuthenticationIdentityNormalizerService', () => {
  const service = new AuthenticationIdentityNormalizerService();

  it.each([
    ['john', { loginName: 'john', normalizedUser: 'john', domain: null, displayName: 'john' }],
    [' JOHN ', { loginName: 'JOHN', normalizedUser: 'john', domain: null, displayName: 'john' }],
    ['DOMAIN\\John', { loginName: 'DOMAIN\\John', normalizedUser: 'john', domain: 'domain', displayName: 'domain\\john' }],
    ['John@Example.COM', { loginName: 'John@Example.COM', normalizedUser: 'john', domain: 'example.com', displayName: 'example.com\\john' }],
  ])('canonicalizes %s', (input, expected) => {
    expect(service.canonicalize(input)).toMatchObject({
      original: input,
      ...expected,
    });
  });

  it.each(['', '   ', 'a\\b\\c', 'domain\\user@realm', 'a@b@c'])(
    'rejects ambiguous or empty identity %s',
    (input) => {
      expect(() => service.canonicalize(input)).toThrow(/identity/i);
    },
  );
});
```

- [ ] **Step 2: Run normalizer test and confirm failure**

Run: `cd backend && npm test -- authentication-identity-normalizer.service.spec`

Expected: FAIL with module not found.

- [ ] **Step 3: Implement normalizer**

```ts
export class AuthenticationIdentityNormalizerService {
  canonicalize(input: string): CanonicalIdentity {
    const loginName = input.trim();
    if (!loginName) throw new Error('authentication identity is empty');
    if (loginName.includes('\\') && loginName.includes('@')) {
      throw new Error('authentication identity is ambiguous');
    }
    const slash = loginName.indexOf('\\');
    if (slash >= 0) {
      const domain = loginName.slice(0, slash).trim().toLowerCase();
      const user = loginName.slice(slash + 1).trim();
      if (!domain || !user || user.includes('\\')) {
        throw new Error('authentication identity is ambiguous');
      }
      const normalizedUser = user.toLowerCase();
      return { original: input, loginName, normalizedUser, domain, displayName: `${domain}\\${normalizedUser}` };
    }
    const at = loginName.indexOf('@');
    if (at >= 0) {
      const user = loginName.slice(0, at).trim();
      const domain = loginName.slice(at + 1).trim().toLowerCase();
      if (!user || !domain || domain.includes('@')) {
        throw new Error('authentication identity is ambiguous');
      }
      const normalizedUser = user.toLowerCase();
      return { original: input, loginName, normalizedUser, domain, displayName: `${domain}\\${normalizedUser}` };
    }
    const normalizedUser = loginName.toLowerCase();
    return { original: input, loginName, normalizedUser, domain: null, displayName: normalizedUser };
  }
}
```

- [ ] **Step 4: Replace flow type**

In `authentication-engine.dto.ts`, replace `AuthenticationFlow` with:

```ts
export type AuthenticationFlowKind =
  | 'admin_login'
  | 'portal_login'
  | 'api_login'
  | 'auth_policy_portal';

export interface AuthenticationEngineRequest {
  flow: AuthenticationFlowKind;
  username: string;
  password: string;
  sourceIp?: string;
}
```

Add `canonicalIdentity: CanonicalIdentity` to provider request and accept result.

- [ ] **Step 5: Update callers**

Change portal use case to call:

```ts
flow: 'portal_login',
```

Change admin login use case to call:

```ts
flow: 'admin_login',
```

Update resolver mapping:

```ts
const profileId =
  flow === 'admin_login'
    ? settings.getAdminAuthenticationProfileId()
    : flow === 'portal_login' || flow === 'auth_policy_portal'
      ? settings.getPortalAuthenticationProfileId()
      : null;
```

Return disabled for `api_login` with message `external api_login authentication is not enabled`.

- [ ] **Step 6: Inject normalizer into engine**

In `AuthenticationEngineService`, canonicalize before provider call and pass `canonicalIdentity` to providers:

```ts
const canonicalIdentity = this.identityNormalizer.canonicalize(request.username);
```

Use `canonicalIdentity.loginName` as provider username.

- [ ] **Step 7: Run flow tests**

Run: `cd backend && npm test -- authentication-identity-normalizer.service.spec authentication-engine.service.spec authenticate-identity.use-case.spec login-user.use-case.spec`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/src/application/services/authentication-identity-normalizer.service.ts backend/src/application/services/authentication-identity-normalizer.service.spec.ts backend/src/application/dtos/authentication-engine.dto.ts backend/src/application/services/authentication-engine.service.ts backend/src/application/services/authentication-engine.service.spec.ts backend/src/application/services/authentication-profile-resolver.service.ts backend/src/application/use-cases/authenticate-identity.use-case.ts backend/src/application/use-cases/authenticate-identity.use-case.spec.ts backend/src/application/use-cases/login-user.use-case.ts backend/src/application/use-cases/login-user.use-case.spec.ts
git commit -m "feat(identity): add canonical identities and flow kinds"
```

---

## Task 3: Authentication Profile Schema And API Contract

**Files:**
- Modify: `backend/src/domain/entities/identity-authentication-profile.entity.ts`
- Test: `backend/src/domain/entities/identity-authentication-profile.entity.spec.ts`
- Modify: `backend/src/infrastructure/persistence/schemas/identity-config.schema.ts`
- Modify: `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts`
- Test: `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.spec.ts`
- Modify: `backend/src/presentation/dtos/identity-config-profile.dto.ts`
- Modify: `backend/src/presentation/dtos/identity-config-profile-response.dto.ts`
- Modify: `backend/src/presentation/mappers/identity-config-response.mapper.ts`
- Modify: `backend/src/application/use-cases/create-authentication-profile.use-case.ts`
- Modify: `backend/src/application/use-cases/update-authentication-profile.use-case.ts`
- Modify: `frontend/src/types/identity/IdentityConfig.ts`
- Modify: `frontend/src/services/identityConfig.ts`

- [ ] **Step 1: Write failing entity tests**

Add tests for required fields and defaults:

```ts
it('stores allowed flows, allow list, RADIUS group retrieval and lockout settings', () => {
  const profile = IdentityAuthenticationProfile.create(
    'auth-1',
    'Auth',
    null,
    true,
    'radius',
    'radius-1',
    'ldap-1',
    'ldap',
    1800,
    now,
    now,
    'test',
    [],
    {
      allowedFlows: ['admin_login', 'portal_login'],
      retrieveUserGroupFromRadius: true,
      allowList: [{ kind: 'group', value: 'admins' }],
      failedAttempts: 3,
      lockoutSeconds: 600,
      requireGroupMappingForUserId: true,
      radiusVsaAsPolicyGroupsCompatibility: false,
    },
  );

  expect(profile.getAllowedFlows()).toEqual(['admin_login', 'portal_login']);
  expect(profile.getRetrieveUserGroupFromRadius()).toBe(true);
  expect(profile.getAllowList()).toEqual([{ kind: 'group', value: 'admins' }]);
  expect(profile.getFailedAttempts()).toBe(3);
  expect(profile.getLockoutSeconds()).toBe(600);
  expect(profile.getRequireGroupMappingForUserId()).toBe(true);
});

it('rejects empty allowed flows', () => {
  expect(() =>
    IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      true,
      'radius',
      'radius-1',
      null,
      'none',
      1800,
      now,
      now,
      'test',
      [],
      { allowedFlows: [] },
    ),
  ).toThrow(/allowedFlows/);
});
```

- [ ] **Step 2: Run entity test and confirm failure**

Run: `cd backend && npm test -- identity-authentication-profile.entity.spec`

Expected: FAIL because constructor does not accept profile options.

- [ ] **Step 3: Add domain types and getters**

Add these exported types:

```ts
export type AuthenticationFlowKind =
  | 'admin_login'
  | 'portal_login'
  | 'api_login'
  | 'auth_policy_portal';

export type AuthenticationProfileAllowListEntry =
  | { kind: 'all' }
  | { kind: 'user'; value: string }
  | { kind: 'group'; value: string };
```

Add readonly fields and getters:

```ts
public getAllowedFlows(): AuthenticationFlowKind[] {
  return [...this.allowedFlows];
}

public getRetrieveUserGroupFromRadius(): boolean {
  return this.retrieveUserGroupFromRadius;
}

public getAllowList(): AuthenticationProfileAllowListEntry[] {
  return this.allowList.map((entry) => ({ ...entry }));
}
```

Keep `groupSource` for existing LDAP/none compatibility, but reject new `radius_vsa` profiles unless `radiusVsaAsPolicyGroupsCompatibility=true` came from migration.

- [ ] **Step 4: Update JSON schema with migration defaults**

In `IdentityAuthenticationProfileRecordSchema`, add:

```ts
allowedFlows: z
  .array(z.enum(['admin_login', 'portal_login', 'api_login', 'auth_policy_portal']))
  .min(1)
  .default(['admin_login', 'portal_login', 'auth_policy_portal']),
retrieveUserGroupFromRadius: z.boolean().default(false),
allowList: z.array(
  z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('all') }).strict(),
    z.object({ kind: z.literal('user'), value: z.string().min(1).max(256) }).strict(),
    z.object({ kind: z.literal('group'), value: z.string().min(1).max(256) }).strict(),
  ]),
).default([{ kind: 'all' }]),
failedAttempts: z.number().int().min(1).max(20).default(5),
lockoutSeconds: z.number().int().min(1).max(86400).default(900),
requireGroupMappingForUserId: z.boolean().default(false),
radiusVsaAsPolicyGroupsCompatibility: z.boolean().default(false),
migrationWarnings: z.array(z.string().min(1).max(256)).default([]),
```

For legacy records with `groupSource='radius_vsa'`, mapper must produce:

```ts
retrieveUserGroupFromRadius: true,
radiusVsaAsPolicyGroupsCompatibility: true,
migrationWarnings: ['identity.policy.radius_vsa_group_dependency'],
```

- [ ] **Step 5: Update create/update DTOs and frontend types**

Expose new fields in backend DTOs and frontend request bodies:

```ts
allowedFlows: AuthenticationFlowKind[];
retrieveUserGroupFromRadius: boolean;
allowList: AuthenticationProfileAllowListEntry[];
failedAttempts: number;
lockoutSeconds: number;
requireGroupMappingForUserId: boolean;
```

Do not expose `radiusVsaAsPolicyGroupsCompatibility` as a normal create/edit body field.

- [ ] **Step 6: Run schema/API tests**

Run: `cd backend && npm test -- identity-authentication-profile.entity.spec identity-config-json.mapper.spec create-authentication-profile.use-case.spec update-authentication-profile.use-case.spec identity-config.controller.spec`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src/domain/entities/identity-authentication-profile.entity.ts backend/src/domain/entities/identity-authentication-profile.entity.spec.ts backend/src/infrastructure/persistence/schemas/identity-config.schema.ts backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.spec.ts backend/src/presentation/dtos/identity-config-profile.dto.ts backend/src/presentation/dtos/identity-config-profile-response.dto.ts backend/src/presentation/mappers/identity-config-response.mapper.ts backend/src/application/use-cases/create-authentication-profile.use-case.ts backend/src/application/use-cases/create-authentication-profile.use-case.spec.ts backend/src/application/use-cases/update-authentication-profile.use-case.ts backend/src/application/use-cases/update-authentication-profile.use-case.spec.ts frontend/src/types/identity/IdentityConfig.ts frontend/src/services/identityConfig.ts
git commit -m "feat(identity): add authentication profile authorization fields"
```

---

## Task 4: Durable Authentication Lockout Store

**Files:**
- Create: `backend/src/application/ports/authentication-lockout-store.interface.ts`
- Create: `backend/src/infrastructure/persistence/schemas/authentication-lockouts.schema.ts`
- Create: `backend/src/infrastructure/persistence/repositories/json-authentication-lockout.store.ts`
- Test: `backend/src/infrastructure/persistence/repositories/json-authentication-lockout.store.spec.ts`
- Modify: `backend/src/modules/authentication-engine.module.ts`

- [ ] **Step 1: Write failing lockout store tests**

```ts
it('persists failed attempts and lockout across store instances', async () => {
  const first = new JsonAuthenticationLockoutStore(fileStore, mutex);
  await first.recordFailure({
    authenticationProfileId: 'auth-1',
    normalizedUser: 'alice',
    domain: null,
    failedAttempts: 3,
    lockoutSeconds: 600,
    now,
  });
  await first.recordFailure({
    authenticationProfileId: 'auth-1',
    normalizedUser: 'alice',
    domain: null,
    failedAttempts: 3,
    lockoutSeconds: 600,
    now: new Date(now.getTime() + 1000),
  });
  const locked = await first.recordFailure({
    authenticationProfileId: 'auth-1',
    normalizedUser: 'alice',
    domain: null,
    failedAttempts: 3,
    lockoutSeconds: 600,
    now: new Date(now.getTime() + 2000),
  });

  expect(locked.kind).toBe('locked');

  const second = new JsonAuthenticationLockoutStore(fileStore, mutex);
  await expect(
    second.getLockout({
      authenticationProfileId: 'auth-1',
      normalizedUser: 'alice',
      domain: null,
      now: new Date(now.getTime() + 3000),
    }),
  ).resolves.toMatchObject({ kind: 'locked' });
});

it('clears state after successful authentication', async () => {
  await store.recordFailure({ authenticationProfileId: 'auth-1', normalizedUser: 'alice', domain: null, failedAttempts: 3, lockoutSeconds: 600, now });
  await store.clear({ authenticationProfileId: 'auth-1', normalizedUser: 'alice', domain: null });

  await expect(
    store.getLockout({ authenticationProfileId: 'auth-1', normalizedUser: 'alice', domain: null, now }),
  ).resolves.toEqual({ kind: 'not_locked' });
});
```

- [ ] **Step 2: Run lockout store test and confirm failure**

Run: `cd backend && npm test -- json-authentication-lockout.store.spec`

Expected: FAIL with module not found.

- [ ] **Step 3: Add lockout port**

```ts
export interface AuthenticationLockoutKey {
  authenticationProfileId: string;
  normalizedUser: string;
  domain: string | null;
}

export interface AuthenticationLockoutFailureCommand extends AuthenticationLockoutKey {
  failedAttempts: number;
  lockoutSeconds: number;
  now: Date;
}

export type AuthenticationLockoutState =
  | { kind: 'not_locked' }
  | { kind: 'locked'; lockedUntil: Date };

export interface IAuthenticationLockoutStore {
  getLockout(key: AuthenticationLockoutKey & { now: Date }): Promise<AuthenticationLockoutState>;
  recordFailure(command: AuthenticationLockoutFailureCommand): Promise<AuthenticationLockoutState>;
  clear(key: AuthenticationLockoutKey): Promise<void>;
}

export const AUTHENTICATION_LOCKOUT_STORE_TOKEN = Symbol('AUTHENTICATION_LOCKOUT_STORE_TOKEN');
```

- [ ] **Step 4: Implement JSON store**

Use `FileStore.readJsonOrDefault`, `FileStore.writeJsonAtomic`, and `Mutex.runExclusive`. Key records by:

```ts
`${authenticationProfileId}:${domain ?? ''}:${normalizedUser}`
```

Persist records:

```ts
{
  authenticationProfileId: string;
  normalizedUser: string;
  domain: string | null;
  failedCount: number;
  firstFailedAt: string;
  lastFailedAt: string;
  lockedUntil: string | null;
}
```

- [ ] **Step 5: Register store in module**

In `AuthenticationEngineModule`, add `JsonAuthenticationLockoutStore` provider and bind it to `AUTHENTICATION_LOCKOUT_STORE_TOKEN`.

- [ ] **Step 6: Run lockout tests**

Run: `cd backend && npm test -- json-authentication-lockout.store.spec`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src/application/ports/authentication-lockout-store.interface.ts backend/src/infrastructure/persistence/schemas/authentication-lockouts.schema.ts backend/src/infrastructure/persistence/repositories/json-authentication-lockout.store.ts backend/src/infrastructure/persistence/repositories/json-authentication-lockout.store.spec.ts backend/src/modules/authentication-engine.module.ts
git commit -m "feat(identity): persist authentication lockout state"
```

---

## Task 5: Authentication Profile Evaluator State Machine

**Files:**
- Create: `backend/src/application/services/authentication-profile-evaluator.service.ts`
- Test: `backend/src/application/services/authentication-profile-evaluator.service.spec.ts`
- Modify: `backend/src/application/dtos/authentication-engine.dto.ts`
- Modify: `backend/src/application/services/authentication-engine.service.ts`
- Test: `backend/src/application/services/authentication-engine.service.spec.ts`

- [ ] **Step 1: Write failing evaluator tests**

```ts
it('denies before provider call when locked out', async () => {
  lockoutStore.getLockout.mockResolvedValue({
    kind: 'locked',
    lockedUntil: new Date('2026-01-01T10:10:00.000Z'),
  });

  const decision = await evaluator.evaluate({
    flow: 'portal_login',
    profile,
    canonicalIdentity,
    providerCall: jest.fn(),
    now,
  });

  expect(decision.kind).toBe('locked_out');
  expect(providerCall).not.toHaveBeenCalled();
});

it('records failed attempt for provider reject', async () => {
  lockoutStore.getLockout.mockResolvedValue({ kind: 'not_locked' });
  providerCall.mockResolvedValue({ kind: 'reject', provider: 'radius', reason: 'Access-Reject', profileId: 'auth-1' });

  const decision = await evaluator.evaluate({ flow: 'portal_login', profile, canonicalIdentity, providerCall, now });

  expect(decision.kind).toBe('provider_rejected');
  expect(lockoutStore.recordFailure).toHaveBeenCalled();
});

it('does not record failed attempt for provider unavailable', async () => {
  lockoutStore.getLockout.mockResolvedValue({ kind: 'not_locked' });
  providerCall.mockResolvedValue({ kind: 'unavailable', provider: 'radius', message: 'socket error', profileId: 'auth-1' });

  const decision = await evaluator.evaluate({ flow: 'portal_login', profile, canonicalIdentity, providerCall, now });

  expect(decision.kind).toBe('provider_unavailable');
  expect(lockoutStore.recordFailure).not.toHaveBeenCalled();
});

it('allows RADIUS group Allow List only when retrieveUserGroupFromRadius is enabled', async () => {
  const result = acceptedRadiusResult({ paloAltoUserGroups: ['vpn-users'] });
  providerCall.mockResolvedValue(result);
  const decision = await evaluator.evaluate({ flow: 'portal_login', profile: profileWithRadiusGroupRetrieval, canonicalIdentity, providerCall, now });

  expect(decision.kind).toBe('authorized');
});
```

- [ ] **Step 2: Run evaluator test and confirm failure**

Run: `cd backend && npm test -- authentication-profile-evaluator.service.spec`

Expected: FAIL with module not found.

- [ ] **Step 3: Add decision/result types**

In `authentication-engine.dto.ts`, define:

```ts
export type AuthenticationProviderResult =
  | AuthenticationProviderAcceptResult
  | { kind: 'reject'; provider?: IdentityAuthenticationProvider; reason: string; profileId?: string }
  | { kind: 'timeout'; provider?: IdentityAuthenticationProvider; message: string; profileId?: string }
  | { kind: 'unavailable'; provider?: IdentityAuthenticationProvider; message: string; profileId?: string }
  | { kind: 'misconfigured'; message: string; profileId?: string }
  | { kind: 'disabled'; message: string };

export type AuthenticationProfileDecision =
  | { kind: 'locked_out'; lockedUntil: Date }
  | { kind: 'provider_rejected'; reason: string }
  | { kind: 'provider_unavailable'; message: string }
  | { kind: 'provider_protocol_error'; message: string }
  | { kind: 'accepted_but_not_allowed'; reason: 'allow_list' | 'flow' }
  | { kind: 'authorized'; providerResult: AuthenticationProviderAcceptResult };
```

- [ ] **Step 4: Implement evaluator**

Evaluation order must be:

```ts
if (!profile.getAllowedFlows().includes(flow)) {
  return { kind: 'accepted_but_not_allowed', reason: 'flow' };
}
const lockout = await this.lockoutStore.getLockout({ ...key, now });
if (lockout.kind === 'locked') return { kind: 'locked_out', lockedUntil: lockout.lockedUntil };
const providerResult = await providerCall();
```

Handle provider results:

- `reject` records failure and returns `provider_rejected`.
- `timeout` and `unavailable` return `provider_unavailable`.
- `misconfigured` returns `provider_protocol_error`.
- `accept` evaluates Allow List.
- Allow List denial records failure and returns `accepted_but_not_allowed`.
- Allow List success clears lockout state and returns `authorized`.

- [ ] **Step 5: Wire engine through evaluator**

In `AuthenticationEngineService.authenticate`, provider call becomes a callback passed to evaluator:

```ts
const decision = await this.profileEvaluator.evaluate({
  flow: request.flow,
  profile: resolved.authenticationProfile,
  canonicalIdentity,
  now: new Date(),
  providerCall: () => service.authenticate(
    {
      username: canonicalIdentity.loginName,
      password: request.password,
      sourceIp: request.sourceIp,
      canonicalIdentity,
    },
    resolved,
  ),
});
```

Map decisions back to existing outward result kinds so controllers keep behavior:

```ts
if (decision.kind === 'authorized') return decision.providerResult;
if (decision.kind === 'locked_out') return { kind: 'reject', reason: 'locked out', profileId: resolved.authenticationProfile.getId() };
if (decision.kind === 'accepted_but_not_allowed') return { kind: 'reject', reason: decision.reason, profileId: resolved.authenticationProfile.getId() };
```

- [ ] **Step 6: Run evaluator and engine tests**

Run: `cd backend && npm test -- authentication-profile-evaluator.service.spec authentication-engine.service.spec`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src/application/services/authentication-profile-evaluator.service.ts backend/src/application/services/authentication-profile-evaluator.service.spec.ts backend/src/application/dtos/authentication-engine.dto.ts backend/src/application/services/authentication-engine.service.ts backend/src/application/services/authentication-engine.service.spec.ts
git commit -m "feat(identity): evaluate authentication profiles as state machine"
```

---

## Task 6: RADIUS Provider Accept Context Without Policy Groups

**Files:**
- Modify: `backend/src/application/services/radius-authentication-provider.service.ts`
- Test: `backend/src/application/services/radius-authentication-provider.service.spec.ts`
- Modify: `backend/src/application/services/authentication-group-resolver.service.ts`
- Create: `backend/src/application/services/authentication-group-resolver.service.spec.ts`

- [ ] **Step 1: Write failing provider tests**

```ts
it('returns typed Palo Alto attributes and does not turn RADIUS user groups into policy groups', async () => {
  const { provider } = service({
    kind: 'accept',
    attributes: {
      generic: { groups: ['filter-users'] },
      paloAlto: {
        adminRole: null,
        adminAccessDomain: null,
        panoramaAdminRole: null,
        panoramaAdminAccessDomain: null,
        userGroups: ['radius-vpn'],
        userDomain: null,
        clientSourceIp: null,
        clientOs: null,
        clientHostname: null,
        globalProtectClientVersion: null,
      },
    },
  });

  const result = await provider.authenticate(request, resolved);

  expect(result.kind).toBe('accept');
  if (result.kind === 'accept') {
    expect(result.groups).toEqual([]);
    expect(result.groupSource).toBe('ldap');
    expect(result.radiusAttributes.paloAlto.userGroups).toEqual(['radius-vpn']);
  }
});
```

- [ ] **Step 2: Run provider tests and confirm failure**

Run: `cd backend && npm test -- radius-authentication-provider.service.spec authentication-group-resolver.service.spec`

Expected: FAIL because current provider reads `result.groups`.

- [ ] **Step 3: Update provider accept result**

Provider accept result must include:

```ts
radiusAttributes: RadiusParsedAttributes | null;
groupSource: UserIdGroupSource;
groupMappingStatus: UserIdGroupMappingStatus;
```

For RADIUS, use typed attributes from authenticator:

```ts
radiusAttributes: result.attributes,
```

- [ ] **Step 4: Change group resolver semantics**

`AuthenticationGroupResolverService.resolve` must not fall back from LDAP failure to normal RADIUS VSA groups. Return:

```ts
{
  groups: [],
  externalId: username,
  source: 'ldap',
  status: 'unavailable',
  diagnostic: lookup.kind,
  error: message,
}
```

Only return `source: 'radius_compat'` when `profile.getRadiusVsaAsPolicyGroupsCompatibility()` is true.

- [ ] **Step 5: Run provider/group tests**

Run: `cd backend && npm test -- radius-authentication-provider.service.spec authentication-group-resolver.service.spec`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/application/services/radius-authentication-provider.service.ts backend/src/application/services/radius-authentication-provider.service.spec.ts backend/src/application/services/authentication-group-resolver.service.ts backend/src/application/services/authentication-group-resolver.service.spec.ts backend/src/application/dtos/authentication-engine.dto.ts
git commit -m "feat(identity): keep RADIUS VSA groups out of policy identity"
```

---

## Task 7: Administrator Authorization From Typed VSA

**Files:**
- Modify: `backend/src/application/services/admin-authorization.service.ts`
- Test: `backend/src/application/services/admin-authorization.service.spec.ts`
- Modify: `backend/src/application/use-cases/login-user.use-case.ts`
- Test: `backend/src/application/use-cases/login-user.use-case.spec.ts`

- [ ] **Step 1: Write failing admin authorization tests**

```ts
it('authorizes RADIUS admin from PaloAlto-Admin-Role before fallback mappings', async () => {
  const decision = await service.authorize(acceptedRadiusAdmin({
    adminRole: 'superuser',
    adminAccessDomain: 'device-admins',
  }));

  expect(decision).toMatchObject({
    kind: 'authorized',
    role: 'super_admin',
    matchedBy: 'palo_alto_admin_role',
    matchedValue: 'superuser',
  });
});

it('denies RADIUS admin accept with no admin role and no fallback mapping', async () => {
  const decision = await service.authorize(acceptedRadiusAdmin({ adminRole: null }));

  expect(decision).toEqual({
    kind: 'denied',
    reason: 'radius admin role VSA not found',
  });
});

it('uses explicit fallback mappings only after typed admin VSA is absent', async () => {
  const decision = await service.authorize(acceptedRadiusAdminWithFallbackGroup('legacy-admins'));

  expect(decision).toMatchObject({
    kind: 'authorized',
    matchedBy: 'radius_vsa',
    matchedValue: 'legacy-admins',
  });
});
```

- [ ] **Step 2: Run admin tests and confirm failure**

Run: `cd backend && npm test -- admin-authorization.service.spec login-user.use-case.spec`

Expected: FAIL because current authorization only checks flattened groups.

- [ ] **Step 3: Add decision match type**

Extend `AdminAuthorizationDecision` authorized shape:

```ts
matchedBy:
  | 'palo_alto_admin_role'
  | 'palo_alto_admin_access_domain'
  | AdminRoleMapping['matchType'];
```

Map Palo Alto dynamic roles:

```ts
const dynamicRoleMap = new Map([
  ['superuser', 'super_admin'],
  ['superreader', 'viewer'],
]);
```

Keep existing local roles as fallback compatibility mappings.

- [ ] **Step 4: Implement admin order**

In `LoginUserUseCase`, keep external admin session creation only after `AuthenticationEngineService` returns accept and `AdminAuthorizationService.authorize()` returns authorized. No User-ID mapping should be created by `LoginUserUseCase`.

- [ ] **Step 5: Run admin tests**

Run: `cd backend && npm test -- admin-authorization.service.spec login-user.use-case.spec`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/application/services/admin-authorization.service.ts backend/src/application/services/admin-authorization.service.spec.ts backend/src/application/use-cases/login-user.use-case.ts backend/src/application/use-cases/login-user.use-case.spec.ts
git commit -m "feat(identity): authorize RADIUS admins from typed VSAs"
```

---

## Task 8: User-ID Runtime Mapping Metadata And Firewall Policy Semantics

**Files:**
- Modify: `proto/services/identity_session_service.proto`
- Generate: `backend/src/infrastructure/grpc/generated/services/identity_session_service.ts`
- Modify: `backend/src/application/ports/identity-session-sync-service.interface.ts`
- Modify: `backend/src/domain/entities/identity-session.entity.ts`
- Test: `backend/src/domain/entities/identity-session.entity.spec.ts`
- Modify: `backend/src/infrastructure/persistence/schemas/identity-sessions.schema.ts`
- Modify: `backend/src/infrastructure/persistence/mappers/identity-session-json.mapper.ts`
- Test: `backend/src/infrastructure/persistence/repositories/json-identity-session.store.spec.ts`
- Modify: `backend/src/application/use-cases/authenticate-identity.use-case.ts`
- Test: `backend/src/application/use-cases/authenticate-identity.use-case.spec.ts`
- Modify: `backend/src/infrastructure/adapters/grpc-identity-session-sync.service.ts`
- Modify: `backend/src/infrastructure/identity/identity-group-refresher.service.ts`
- Modify: `backend/src/infrastructure/identity/identity-session-replay.service.ts`
- Modify: `crates/raptorgate/src/identity/session.rs`
- Modify: `crates/raptorgate/src/identity/store.rs`
- Modify: `crates/raptorgate/src/identity/service.rs`
- Modify: `crates/raptorgate/src/policy/policy_evaluator.rs`

- [ ] **Step 1: Write failing backend session tests**

```ts
it('persists group source and group mapping status', () => {
  const session = IdentitySession.create(
    'session-1',
    'alice',
    IpAddress.create('192.0.2.10'),
    now,
    expires,
    ['admins'],
    '192.0.2.1',
    'portal',
    'uid=alice,dc=example,dc=com',
    '00:00:00:00:00:00',
    'ldap',
    'resolved',
  );

  const record = IdentitySessionJsonMapper.toRecord(session);
  expect(record.groupSource).toBe('ldap');
  expect(record.groupMappingStatus).toBe('resolved');
});
```

- [ ] **Step 2: Write failing Rust session test**

In `crates/raptorgate/src/identity/session.rs`, add:

```rust
#[test]
fn parses_group_source_and_mapping_status() {
    let mut proto = sample_proto();
    proto.group_source = "ldap".into();
    proto.group_mapping_status = "resolved".into();

    let session = IdentitySession::try_from_proto(proto).unwrap();

    assert_eq!(session.group_source, UserIdGroupSource::Ldap);
    assert_eq!(session.group_mapping_status, UserIdGroupMappingStatus::Resolved);
}
```

- [ ] **Step 3: Run tests and confirm failure**

Run: `cd backend && npm test -- identity-session.entity.spec json-identity-session.store.spec authenticate-identity.use-case.spec`

Expected: FAIL on missing group metadata.

Run: `cargo test -p ngfw identity::session::tests::parses_group_source_and_mapping_status`

Expected: FAIL on missing proto fields or Rust fields.

- [ ] **Step 4: Add proto fields**

In `proto/services/identity_session_service.proto`, add:

```proto
string group_source         = 11;
string group_mapping_status = 12;
```

Run: `cd backend && npm run proto:generate`

Expected: generated TypeScript updates `IdentityManagerUserSession`.

- [ ] **Step 5: Update backend runtime entity and sync**

Add `groupSource` and `groupMappingStatus` to `IdentitySession.create`, getters, JSON schema, mapper, sync payload, gRPC sync service, replay, refresher, and authenticate use case.

`AuthenticateIdentityUseCase` must pass:

```ts
groupSource: result.groupSource,
groupMappingStatus: result.groupMappingStatus,
```

If `result.groupMappingStatus === 'required_but_failed'`, do not create a session and throw `AuthenticationRejectedException`.

- [ ] **Step 6: Update Rust runtime session**

Add enums:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserIdGroupSource {
    Ldap,
    Local,
    RadiusCompat,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserIdGroupMappingStatus {
    Resolved,
    Unavailable,
    Disabled,
    RequiredButFailed,
}
```

Parse strings from proto. Empty strings default to `None` and `Disabled` for backward compatibility.

- [ ] **Step 7: Gate policy group matching by status**

In `PolicyEvaluator::pattern_matches_group`, make `identity_group` match only when:

- session exists,
- `group_mapping_status == Resolved`,
- group is present.

When `group_source == RadiusCompat` and a group match succeeds, emit:

```rust
tracing::warn!(
    event = "auth.compat.radius_vsa_policy_group.used",
    username = %session.username,
    "matched migrated RADIUS VSA compatibility group"
);
```

- [ ] **Step 8: Run backend and Rust tests**

Run: `cd backend && npm test -- identity-session.entity.spec json-identity-session.store.spec authenticate-identity.use-case.spec`

Expected: PASS.

Run: `cargo test -p ngfw identity::`

Expected: PASS.

Run: `cargo test -p ngfw policy::policy_evaluator`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add proto/services/identity_session_service.proto backend/src/infrastructure/grpc/generated/services/identity_session_service.ts backend/src/application/ports/identity-session-sync-service.interface.ts backend/src/domain/entities/identity-session.entity.ts backend/src/domain/entities/identity-session.entity.spec.ts backend/src/infrastructure/persistence/schemas/identity-sessions.schema.ts backend/src/infrastructure/persistence/mappers/identity-session-json.mapper.ts backend/src/infrastructure/persistence/repositories/json-identity-session.store.spec.ts backend/src/application/use-cases/authenticate-identity.use-case.ts backend/src/application/use-cases/authenticate-identity.use-case.spec.ts backend/src/infrastructure/adapters/grpc-identity-session-sync.service.ts backend/src/infrastructure/identity/identity-group-refresher.service.ts backend/src/infrastructure/identity/identity-session-replay.service.ts crates/raptorgate/src/identity/session.rs crates/raptorgate/src/identity/store.rs crates/raptorgate/src/identity/service.rs crates/raptorgate/src/policy/policy_evaluator.rs
git commit -m "feat(identity): sync User-ID group mapping metadata"
```

---

## Task 9: Migration Diagnostics And Compatibility Mode

**Files:**
- Modify: `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts`
- Test: `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.spec.ts`
- Modify: `backend/src/application/services/authentication-group-resolver.service.ts`
- Test: `backend/src/application/services/authentication-group-resolver.service.spec.ts`
- Modify: `backend/src/application/use-cases/authenticate-identity.use-case.spec.ts`

- [ ] **Step 1: Write failing migration tests**

```ts
it('migrates legacy radius_vsa group source into compatibility mode with warning', () => {
  const record = IdentityConfigJsonMapper.toRecord(config());
  record.authentication_profiles.items[0] = {
    ...record.authentication_profiles.items[0],
    groupSource: 'radius_vsa',
  };
  delete (record.authentication_profiles.items[0] as any).retrieveUserGroupFromRadius;
  delete (record.authentication_profiles.items[0] as any).radiusVsaAsPolicyGroupsCompatibility;

  const domain = IdentityConfigJsonMapper.toDomain(record);
  const profile = domain.getAuthenticationProfiles()[0];

  expect(profile.getRetrieveUserGroupFromRadius()).toBe(true);
  expect(profile.getRadiusVsaAsPolicyGroupsCompatibility()).toBe(true);
  expect(profile.getMigrationWarnings()).toContain('identity.policy.radius_vsa_group_dependency');
});
```

- [ ] **Step 2: Write failing compatibility resolver test**

```ts
it('uses RADIUS VSA policy groups only in migrated compatibility mode', async () => {
  const resolution = await resolver.resolve(
    resolvedWithRadiusCompatProfile,
    'alice',
    { generic: { groups: [] }, paloAlto: { ...emptyPaloAlto, userGroups: ['legacy-radius'] } },
  );

  expect(resolution).toMatchObject({
    groups: ['legacy-radius'],
    source: 'radius_compat',
    status: 'resolved',
    diagnostic: 'deprecated_compatibility',
  });
});
```

- [ ] **Step 3: Run migration tests and confirm failure**

Run: `cd backend && npm test -- identity-config-json.mapper.spec authentication-group-resolver.service.spec`

Expected: FAIL on missing migration warnings and compatibility source.

- [ ] **Step 4: Implement mapper migration**

When a persisted record has `groupSource='radius_vsa'` and lacks explicit new fields, mapper must produce domain profile options:

```ts
retrieveUserGroupFromRadius: true,
radiusVsaAsPolicyGroupsCompatibility: true,
migrationWarnings: [
  'identity.radius_vsa.allow_list_migration',
  'identity.policy.radius_vsa_group_dependency',
],
```

New create/update paths must not set compatibility true.

- [ ] **Step 5: Implement compatibility audit log**

When resolver returns `radius_compat`, log:

```ts
this.logger.warn({
  event: 'auth.compat.radius_vsa_policy_group.used',
  message: 'migrated RADIUS VSA compatibility group source used',
  username,
  profileId: resolved.authenticationProfile.getId(),
  groupCount: groups.length,
});
```

- [ ] **Step 6: Run migration tests**

Run: `cd backend && npm test -- identity-config-json.mapper.spec authentication-group-resolver.service.spec`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.spec.ts backend/src/application/services/authentication-group-resolver.service.ts backend/src/application/services/authentication-group-resolver.service.spec.ts
git commit -m "feat(identity): migrate legacy RADIUS VSA group compatibility"
```

---

## Task 10: End-To-End Slice Verification

**Files:**
- All files modified by Tasks 1-9.

- [ ] **Step 1: Run focused backend test set**

Run:

```bash
cd backend && npm test -- radius-packet.spec authentication-identity-normalizer.service.spec authentication-profile-evaluator.service.spec json-authentication-lockout.store.spec radius-authentication-provider.service.spec authentication-group-resolver.service.spec admin-authorization.service.spec authentication-engine.service.spec authenticate-identity.use-case.spec login-user.use-case.spec identity-config-json.mapper.spec identity-session.entity.spec json-identity-session.store.spec create-authentication-profile.use-case.spec update-authentication-profile.use-case.spec
```

Expected: PASS, all listed suites green.

- [ ] **Step 2: Run backend build**

Run:

```bash
cd backend && npm run build
```

Expected: TypeScript build succeeds and generated proto is current.

- [ ] **Step 3: Run focused Rust tests**

Run:

```bash
cargo test -p ngfw identity::
```

Expected: PASS.

Run:

```bash
cargo test -p ngfw policy::policy_evaluator
```

Expected: PASS.

- [ ] **Step 4: Run full backend and Rust test suites**

Run:

```bash
cd backend && npm test
```

Expected: PASS.

Run:

```bash
cargo test -p ngfw
```

Expected: PASS.

- [ ] **Step 5: Scan for forbidden semantic regressions**

Run:

```bash
rg -n "groupSource: 'radius_vsa'|source === 'radius_vsa'|extractGroupsFromAttributes|flow: 'portal'|flow: 'admin'" backend/src crates/raptorgate/src
```

Expected:

- No active provider/runtime path uses `radius_vsa` except migration compatibility tests and explicit fallback admin mapping.
- No code calls `extractGroupsFromAttributes`.
- No engine caller uses legacy `'portal'` or `'admin'` flow names.

- [ ] **Step 6: Commit final fixes if verification changed files**

```bash
git add backend proto crates frontend
git commit -m "test(identity): verify RADIUS PAP semantic refactor"
```

Skip this commit only when `git status --short` is empty after verification.

---

## Final Acceptance Criteria

- RADIUS PAP Access-Accept returns typed Palo Alto VSA fields.
- `PaloAlto-Admin-Role` and `PaloAlto-User-Group` are never flattened into the same authorization group list.
- Authentication Profile Allow List gates provider accepts.
- Empty non-local Allow List denies login.
- Lockout is checked before provider calls and survives backend restart.
- Provider unavailable does not increment failed attempts.
- Provider reject and Allow List denial increment failed attempts.
- Admin login consumes typed admin VSA after Authentication Profile authorization and creates no User-ID mapping.
- Portal login creates User-ID mapping only after Authentication Profile authorization.
- Normal RADIUS user groups do not become Security Policy `identity_group`.
- LDAP group lookup failure can create a User-ID mapping with empty groups, `groupSource='ldap'`, and `groupMappingStatus='unavailable'` when the profile allows it.
- `requireGroupMappingForUserId=true` denies session creation when group lookup fails.
- Migrated compatibility uses `groupSource='radius_compat'`, emits `auth.compat.radius_vsa_policy_group.used`, and is impossible to create through normal new profile DTOs.
- `api_login` external RADIUS remains disabled.
- Backend build, focused Jest suites, full Jest suite, focused Rust tests, and full Rust suite pass.
