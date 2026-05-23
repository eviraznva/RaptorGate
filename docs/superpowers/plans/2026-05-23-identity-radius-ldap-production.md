# Production Identity, RADIUS, and LDAP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish RaptorGate identity as a production feature: provider config, RADIUS/LDAP auth, group mapping, authentication sequences, portal enforcement, admin role mapping, runtime sessions with endpoint binding, firewall policy enforcement, diagnostics, and per-user visibility.

**Architecture:** Backend remains the identity control plane and the only component that talks to RADIUS/LDAP or stores provider secrets. Firewall receives runtime identity sessions over `IdentitySessionService`, enriches packet context before policy, and emits identity activity. Durable config snapshots keep identity config for import/export/diff/rollback; active firewall config push carries no provider secrets and has an explicit non-secret identity boundary.

**Tech Stack:** TypeScript, NestJS, Zod, Jest, Node UDP/TCP/TLS, protobuf3, gRPC, React/RTK Query, Rust 2024, Tokio, tonic/prost, existing vagrant lab.

**Design Spec:** `docs/superpowers/specs/2026-05-23-identity-radius-ldap-production-design.md`

---

## Current Baseline

Use the current aggregate model:

- `backend/src/domain/entities/identity-configuration.entity.ts`
- `backend/src/infrastructure/persistence/repositories/json-identity-config.repository.ts`
- `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts`
- `backend/src/presentation/controllers/identity-config.controller.ts`

Do not recreate the old Issue A design with separate RADIUS/LDAP/auth/settings repositories. The current single `IdentityConfiguration` aggregate is the source of truth.

Preserve ADR 0001:

- Backend performs provider authentication and group resolving.
- Firewall never connects to RADIUS/LDAP.
- Provider secrets never appear in active gRPC config sent to firewall.

## File Structure

**Create**

- `backend/src/domain/entities/identity-authentication-sequence.entity.ts`: ordered profile fallback model.
- `backend/src/domain/entities/identity-group.entity.ts`: local/LDAP/RADIUS group catalog and local membership.
- `backend/src/domain/entities/radius-server-endpoint.entity.ts`: one endpoint in an ordered RADIUS profile.
- `backend/src/domain/entities/ldap-server-endpoint.entity.ts`: one endpoint in an ordered LDAP profile.
- `backend/src/domain/value-objects/mac-address.vo.ts`: validated MAC address or null at DTO boundary.
- `backend/src/application/services/authentication-sequence-resolver.service.ts`: profile/sequence resolution and fallback execution.
- `backend/src/application/services/identity-group-catalog.service.ts`: local group merge, rule reference checks, LDAP group registration.
- `backend/src/application/ports/firewall-endpoint-identity-query-service.interface.ts`: backend port for IP-to-MAC lookup.
- `backend/src/infrastructure/adapters/grpc-firewall-endpoint-identity-query.service.ts`: gRPC adapter for endpoint metadata lookup.
- `backend/src/application/services/identity-activity-aggregator.service.ts`: per-user activity windows.
- `backend/src/presentation/controllers/identity-groups.controller.ts`: group CRUD and sync diagnostics.
- `backend/src/presentation/controllers/identity-activity.controller.ts`: activity aggregate API.
- `crates/raptorgate/src/identity/activity.rs`: firewall identity activity event model.
- `crates/raptorgate/src/identity/endpoint.rs`: endpoint binding metadata and MAC validation.

**Modify**

- `backend/src/domain/entities/identity-configuration.entity.ts`
- `backend/src/domain/entities/radius-server-profile.entity.ts`
- `backend/src/domain/entities/ldap-server-profile.entity.ts`
- `backend/src/domain/entities/identity-authentication-profile.entity.ts`
- `backend/src/domain/entities/identity-settings.entity.ts`
- `backend/src/domain/entities/identity-session.entity.ts`
- `backend/src/domain/value-objects/config-snapshot-payload.interface.ts`
- `backend/src/infrastructure/persistence/schemas/identity-config.schema.ts`
- `backend/src/infrastructure/persistence/schemas/identity-sessions.schema.ts`
- `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts`
- `backend/src/infrastructure/persistence/mappers/identity-session-json.mapper.ts`
- `backend/src/infrastructure/persistence/mappers/config-payload.mapper.ts`
- `backend/src/infrastructure/adapters/radius/radius-packet.ts`
- `backend/src/infrastructure/adapters/udp-radius-authenticator.ts`
- `backend/src/infrastructure/adapters/ldap/tcp-ldap-client.ts`
- `backend/src/infrastructure/adapters/ldap/ldap-message.ts`
- `backend/src/infrastructure/adapters/ldap/tcp-ldap-authenticator.ts`
- `backend/src/infrastructure/adapters/ldap/tcp-ldap-directory.ts`
- `backend/src/application/services/radius-authentication-provider.service.ts`
- `backend/src/application/services/ldap-authentication-provider.service.ts`
- `backend/src/application/services/authentication-engine.service.ts`
- `backend/src/application/services/authentication-profile-resolver.service.ts`
- `backend/src/application/services/identity-group-resolver.service.ts`
- `backend/src/application/services/admin-authorization.service.ts`
- `backend/src/application/use-cases/authenticate-identity.use-case.ts`
- `backend/src/application/use-cases/login-user.use-case.ts`
- `backend/src/application/use-cases/update-identity-settings.use-case.ts`
- `backend/src/presentation/controllers/identity-config.controller.ts`
- `backend/src/presentation/controllers/identity.controller.ts`
- `backend/src/presentation/mappers/identity-config-response.mapper.ts`
- `backend/src/presentation/dtos/identity-config-profile.dto.ts`
- `backend/src/presentation/dtos/identity-config-profile-response.dto.ts`
- `backend/src/modules/identity.module.ts`
- `backend/src/modules/authentication-engine.module.ts`
- `backend/src/modules/config-snapshot.module.ts`
- `proto/services/identity_session_service.proto`
- `proto/services/query_service.proto`
- `proto/services/config_snapshot_service.proto`
- `proto/config/config_models.proto`
- `crates/raptorgate/src/identity/session.rs`
- `crates/raptorgate/src/identity/store.rs`
- `crates/raptorgate/src/identity/enforcement.rs`
- `crates/raptorgate/src/identity/service.rs`
- `crates/raptorgate/src/pipeline/wrappers.rs`
- `crates/raptorgate/src/policy/policy_evaluator.rs`
- `crates/raptorgate/src/query_server.rs`
- `frontend/src/types/identity/IdentityConfig.ts`
- `frontend/src/types/identity/IdentitySession.ts`
- `frontend/src/services/identityConfig.ts`
- `frontend/src/services/identitySessions.ts`
- `frontend/src/pages/Identity.tsx`
- `docs/identity-radius-manual-tests.md`
- `docs/identity-frontend-manual-tests.md`

**Do not modify**

- TLS L4 inspection plans.
- NAT/DNS/IPS behavior except where identity fields are emitted in existing session/activity DTOs.
- Local break-glass login precedence.

---

## Task 1: Mark the Old Issue A Plan as Superseded

**Files:**

- Modify: `docs/superpowers/plans/2026-04-30-radius-issue-a-first-class-identity-config.md`

- [ ] **Step 1: Add a superseded notice below the title**

Insert this block after the `# Issue A` heading:

```markdown
> Superseded by `docs/superpowers/specs/2026-05-23-identity-radius-ldap-production-design.md` and `docs/superpowers/plans/2026-05-23-identity-radius-ldap-production.md`.
> This file remains historical context for the first configuration-only issue. Do not execute it as the production RADIUS/LDAP plan.
```

- [ ] **Step 2: Verify the notice is visible**

Run:

```bash
sed -n '1,8p' docs/superpowers/plans/2026-04-30-radius-issue-a-first-class-identity-config.md
```

Expected: the superseded notice appears before the agentic-worker header.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/2026-04-30-radius-issue-a-first-class-identity-config.md
git commit -m "docs(identity): supersede old radius issue plan"
```

---

## Task 2: Lock the Identity Snapshot Boundary

**Files:**

- Modify: `backend/src/infrastructure/persistence/mappers/config-payload.mapper.spec.ts`
- Modify: `backend/src/infrastructure/adapters/grpc-config-snapshot-push.service.spec.ts`
- Modify: `backend/src/infrastructure/adapters/grpc-config-snapshot-push.service.ts`
- Modify: `backend/src/domain/value-objects/config-snapshot-payload.interface.ts`
- Modify: `proto/services/config_snapshot_service.proto`
- Modify: `proto/config/config_models.proto`

- [ ] **Step 1: Write snapshot preservation tests**

In `backend/src/infrastructure/persistence/mappers/config-payload.mapper.spec.ts`, add tests proving durable snapshots keep `identity_config`:

```ts
it('preserves production identity_config through durable snapshot mapping', () => {
  const now = new Date('2026-05-23T10:00:00.000Z');
  const payload = configPayloadWithIdentity({
    radiusName: 'corp-radius',
    ldapName: 'corp-ad',
    authName: 'corp-portal',
    now,
  });

  const record = mapConfigSnapshotToPayloadRecord(snapshotFromPayload(payload));
  const mapped = mapConfigBundlePayloadToDomain(snapshotFromRecord(record));

  expect(mapped.bundle.identity_config.radius_server_profiles.items[0].getName()).toBe('corp-radius');
  expect(mapped.bundle.identity_config.ldap_server_profiles.items[0].getName()).toBe('corp-ad');
  expect(mapped.bundle.identity_config.authentication_profiles.items[0].getName()).toBe('corp-portal');
});
```

Use local helper functions in the spec file. Do not create production helpers for this test.

- [ ] **Step 2: Write active push boundary tests**

In `backend/src/infrastructure/adapters/grpc-config-snapshot-push.service.spec.ts`, add tests proving the active firewall push does not carry provider secrets:

```ts
it('does not push RADIUS or LDAP provider secrets to firewall active config', async () => {
  const service = serviceWithGrpcClient(capturingClient);
  const snapshot = activeSnapshotWithIdentitySecretRefs();

  await service.pushActiveSnapshot(snapshot, 'apply');

  const request = capturingClient.lastPushRequest();
  expect(JSON.stringify(request)).not.toContain('secret://identity/radius/corp');
  expect(JSON.stringify(request)).not.toContain('secret://identity/ldap/corp');
  expect(request.snapshot?.bundle?.identity).toBeDefined();
});
```

The expected `identity` value must be either an empty non-secret catalog or a typed catalog of group names. Pick one and keep it consistent in proto and mapper.

- [ ] **Step 3: Make proto boundary explicit**

Replace the ambiguous provider-looking `IdentityBundle identity = 11` use with a non-secret catalog message:

```proto
message IdentityPolicyCatalog {
  repeated UserGroup user_groups = 1;
  repeated IdentityUser identity_users = 2;
}
```

Keep field number `11` in `ConfigBundle` for compatibility:

```proto
raptorgate.config.IdentityPolicyCatalog identity = 11;
```

Provider profiles, bind DNs, shared secret refs, and LDAP endpoint hosts do not belong in this message.

- [ ] **Step 4: Update backend active push mapper**

In `grpc-config-snapshot-push.service.ts`, replace `identity: undefined` with an explicit mapper that emits only the non-secret catalog:

```ts
identity: mapIdentityPolicyCatalog(payload.bundle.identity_config),
```

The mapper returns empty arrays until Task 8 adds group catalog data:

```ts
function mapIdentityPolicyCatalog(): { userGroups: []; identityUsers: [] } {
  return { userGroups: [], identityUsers: [] };
}
```

- [ ] **Step 5: Generate protobuf code**

Run:

```bash
cd backend
bun run proto:generate
```

Run:

```bash
cargo test -p ngfw identity::
```

Expected: generated code compiles and existing identity runtime tests pass.

- [ ] **Step 6: Run backend mapper tests**

Run:

```bash
cd backend
bun test -- config-payload.mapper.spec.ts grpc-config-snapshot-push.service.spec.ts
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add proto backend/src
git commit -m "fix(identity): make firewall snapshot boundary explicit"
```

---

## Task 3: Extend the Identity Domain Aggregate

**Files:**

- Create: `backend/src/domain/entities/radius-server-endpoint.entity.ts`
- Create: `backend/src/domain/entities/ldap-server-endpoint.entity.ts`
- Create: `backend/src/domain/entities/identity-authentication-sequence.entity.ts`
- Create: `backend/src/domain/entities/identity-group.entity.ts`
- Modify: `backend/src/domain/entities/radius-server-profile.entity.ts`
- Modify: `backend/src/domain/entities/ldap-server-profile.entity.ts`
- Modify: `backend/src/domain/entities/identity-authentication-profile.entity.ts`
- Modify: `backend/src/domain/entities/identity-configuration.entity.ts`
- Test: `backend/src/domain/entities/identity-configuration.entity.spec.ts`
- Test: `backend/src/domain/entities/identity-authentication-profile.entity.spec.ts`

- [ ] **Step 1: Add failing aggregate tests**

Add tests for:

- duplicate RADIUS endpoint priorities rejected,
- active RADIUS profile requires at least one active endpoint,
- active LDAP profile requires at least one active endpoint,
- auth sequence rejects missing profile references,
- group names are unique,
- deleting a referenced group is rejected by the domain service in Task 8.

Example test:

```ts
it('rejects authentication sequence references to missing profiles', () => {
  const sequence = IdentityAuthenticationSequence.create(
    'seq-1',
    'Corp fallback',
    null,
    true,
    ['missing-profile'],
    true,
    false,
    now,
    now,
    'admin',
  );

  expect(() =>
    IdentityConfiguration.create(
      [],
      [],
      [],
      [sequence],
      [],
      IdentitySettings.create(null, null, null, null),
    ),
  ).toThrow(IdentityConfigIsInvalidException);
});
```

Run:

```bash
cd backend
bun test -- identity-configuration.entity.spec.ts identity-authentication-profile.entity.spec.ts
```

Expected: FAIL because the new entities and constructor arguments do not exist.

- [ ] **Step 2: Add endpoint entities**

Create `RadiusServerEndpoint` and `LdapServerEndpoint` with:

```ts
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
}
```

`LdapServerEndpoint` has the same fields except `sharedSecretRef`.

Validation:

- id/name/host are non-empty.
- port is `1..65535`.
- priority is integer `1..65535`.
- RADIUS `sharedSecretRef` uses `SecretRef.create`.

- [ ] **Step 3: Extend provider profiles**

Change RADIUS profile to own `RadiusServerEndpoint[]` and keep legacy getters for the first endpoint during migration:

```ts
public getServers(): RadiusServerEndpoint[] {
  return [...this.servers];
}
```

Change LDAP profile to own `LdapServerEndpoint[]`, server type, base DN, TLS verification, connect/search timeout, retry interval, and group mapping fields.

- [ ] **Step 4: Add authentication sequence entity**

Create `IdentityAuthenticationSequence` with getters for profile IDs, `exitOnReject`, and `useDomainRouting`. Validation rejects empty active sequences and duplicate profile IDs.

- [ ] **Step 5: Add identity group entity**

Create `IdentityGroup` with `source: 'local' | 'ldap' | 'radius_vsa'` and members:

```ts
export interface IdentityGroupMember {
  principal: string;
  principalType: 'username' | 'external_id';
}
```

`ldap` and `radius_vsa` groups may have empty `members`. `local` groups may have members and must normalize duplicates.

- [ ] **Step 6: Extend aggregate constructor**

`IdentityConfiguration.create` signature becomes:

```ts
public static create(
  radiusServerProfiles: RadiusServerProfile[],
  ldapServerProfiles: LdapServerProfile[],
  authenticationProfiles: IdentityAuthenticationProfile[],
  authenticationSequences: IdentityAuthenticationSequence[],
  identityGroups: IdentityGroup[],
  settings: IdentitySettings,
): IdentityConfiguration
```

`empty()` passes empty arrays for new collections.

- [ ] **Step 7: Run entity tests**

Run:

```bash
cd backend
bun test -- identity-configuration.entity.spec.ts identity-authentication-profile.entity.spec.ts
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/src/domain/entities
git commit -m "feat(identity): extend production identity aggregate"
```

---

## Task 4: Migrate JSON Schema and Mappers Without Breaking Existing Config

**Files:**

- Modify: `backend/src/infrastructure/persistence/schemas/identity-config.schema.ts`
- Modify: `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts`
- Test: `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.spec.ts`
- Test: `backend/src/infrastructure/persistence/repositories/json-identity-config.repository.spec.ts`

- [ ] **Step 1: Add mapper tests for legacy and production records**

Add one test where legacy RADIUS has `host`, `port`, and `sharedSecretRef`, and mapper converts it to one endpoint with `priority=1`.

Add one test where production RADIUS has `servers[]` and round-trips all endpoints.

Add one test where legacy LDAP has `host`, `port`, `tlsMode` and mapper converts it to one endpoint.

Run:

```bash
cd backend
bun test -- identity-config-json.mapper.spec.ts json-identity-config.repository.spec.ts
```

Expected: FAIL until schema and mapper accept both shapes.

- [ ] **Step 2: Update Zod schemas**

`IdentityConfigurationRecordSchema` accepts:

```ts
authenticationSequences: z.array(AuthenticationSequenceRecordSchema).default([]),
identityGroups: z.array(IdentityGroupRecordSchema).default([]),
```

RADIUS and LDAP profile records accept both old single-endpoint fields and new `servers`.

- [ ] **Step 3: Update record-to-domain mapper**

Mapping rules:

- If `servers` is present, use it.
- If `servers` is absent, create one endpoint from legacy host/port fields.
- Preserve legacy `host`, `port`, and secret fields on write only if existing tests require backwards compatibility. The production writer should emit `servers[]`.

- [ ] **Step 4: Update payload-to-record mapper**

`IdentityConfigJsonMapper.payloadToRecord` writes:

- `radiusServerProfiles`
- `ldapServerProfiles`
- `authenticationProfiles`
- `authenticationSequences`
- `identityGroups`
- `settings`

No plaintext secret values are written.

- [ ] **Step 5: Run mapper and repository tests**

Run:

```bash
cd backend
bun test -- identity-config-json.mapper.spec.ts json-identity-config.repository.spec.ts config-payload.mapper.spec.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/infrastructure/persistence backend/src/domain/value-objects
git commit -m "feat(identity): migrate identity config schema"
```

---

## Task 5: Make RADIUS Production-Grade for Supported Protocols

**Files:**

- Modify: `backend/src/infrastructure/adapters/radius/radius-packet.ts`
- Modify: `backend/src/infrastructure/adapters/radius/radius-packet.spec.ts`
- Modify: `backend/src/infrastructure/adapters/udp-radius-authenticator.ts`
- Modify: `backend/src/application/ports/radius-authenticator.interface.ts`
- Modify: `backend/src/application/services/authentication-provider-options.ts`
- Modify: `backend/src/application/services/radius-authentication-provider.service.ts`
- Test: `backend/src/application/services/radius-authentication-provider.service.spec.ts`
- Test: `backend/src/application/use-cases/test-radius-profile.use-case.spec.ts`

- [ ] **Step 1: Add failing VSA parsing tests**

In `radius-packet.spec.ts`, add a test where:

- Palo Alto vendor id is `25461`,
- vendor type `1` contains `superuser`,
- vendor type `5` contains `admins`,
- parsed result has `adminRole='superuser'` and `userGroups=['admins']`.

Expected type:

```ts
expect(extractRadiusAttributes(attributes)).toEqual({
  userGroups: ['admins'],
  adminRole: 'superuser',
  accessDomain: null,
  panoramaAdminRole: null,
  panoramaAccessDomain: null,
  userDomain: null,
  rawDiagnostics: [],
});
```

Run:

```bash
cd backend
bun test -- radius-packet.spec.ts
```

Expected: FAIL because only `extractGroupsFromAttributes` exists.

- [ ] **Step 2: Replace group-only extraction**

Add:

```ts
export interface RadiusAttributeResult {
  userGroups: string[];
  adminRole: string | null;
  accessDomain: string | null;
  panoramaAdminRole: string | null;
  panoramaAccessDomain: string | null;
  userDomain: string | null;
  rawDiagnostics: string[];
}
```

Export `extractRadiusAttributes(attributes: Buffer): RadiusAttributeResult`.

Keep `extractGroupsFromAttributes` as a compatibility wrapper returning `extractRadiusAttributes(attributes).userGroups` until all call sites move.

- [ ] **Step 3: Add multi-server failover tests**

In `udp-radius-authenticator.ts` tests or provider service tests, build a fake authenticator with two endpoints:

- endpoint 1 returns timeout,
- endpoint 2 returns accept.

Expected provider result is `accept` and diagnostic includes attempted endpoint names.

- [ ] **Step 4: Update authenticator request shape**

Change `RadiusAuthRequest.server` to `RadiusAuthRequest.profile` with ordered servers:

```ts
export interface RadiusAuthProfileOptions {
  authenticationProtocol: 'pap';
  timeoutMs: number;
  retries: number;
  nasIp: string;
  nasIdentifier: string;
  calledStationId: string | null;
  servers: RadiusAuthServerOptions[];
}
```

Validation rejects any protocol not implemented by the adapter. For this task, the supported set is exactly `pap`; unsupported values fail at config validation.

- [ ] **Step 5: Implement ordered endpoint attempts**

`UdpRadiusAuthenticator.authenticate` loops endpoints by priority. For each endpoint it performs `retries + 1` sends. Reject returns immediately. Timeout advances to the next endpoint. Invalid response authenticator returns `error` for that endpoint and advances unless no endpoints remain.

- [ ] **Step 6: Update provider service**

`RadiusAuthenticationProviderService` maps typed RADIUS attributes into:

- `groups` from `userGroups`,
- `adminRole` on accepted result diagnostics,
- `groupSource='radius_vsa'` only when groups came from user group attributes.

- [ ] **Step 7: Run RADIUS tests**

Run:

```bash
cd backend
bun test -- radius-packet.spec.ts radius-authentication-provider.service.spec.ts test-radius-profile.use-case.spec.ts
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/src/infrastructure/adapters/radius backend/src/infrastructure/adapters/udp-radius-authenticator.ts backend/src/application
git commit -m "feat(identity): add ordered radius endpoints and typed attributes"
```

---

## Task 6: Implement LDAP TLS Modes and Profile-Scoped Group Mapping

**Files:**

- Modify: `backend/src/infrastructure/adapters/ldap/ldap-message.ts`
- Modify: `backend/src/infrastructure/adapters/ldap/ldap-message.spec.ts`
- Modify: `backend/src/infrastructure/adapters/ldap/tcp-ldap-client.ts`
- Modify: `backend/src/infrastructure/adapters/ldap/tcp-ldap-authenticator.ts`
- Modify: `backend/src/infrastructure/adapters/ldap/tcp-ldap-directory.ts`
- Modify: `backend/src/application/ports/ldap-directory.interface.ts`
- Modify: `backend/src/application/ports/ldap-authenticator.interface.ts`
- Modify: `backend/src/application/services/ldap-authentication-provider.service.ts`
- Modify: `backend/src/application/services/identity-group-resolver.service.ts`
- Test: `backend/src/infrastructure/adapters/ldap/tcp-ldap-directory.spec.ts`
- Test: `backend/src/application/services/ldap-authentication-provider.service.spec.ts`
- Test: `backend/src/application/services/identity-group-resolver.service.spec.ts`

- [ ] **Step 1: Add failing StartTLS BER tests**

In `ldap-message.spec.ts`, add an encoder test for StartTLS extended request:

```ts
it('encodes LDAP StartTLS extended request', () => {
  const packet = encodeStartTlsRequest(7);

  expect(tryReadLdapFrame(packet)?.message.messageId).toBe(7);
  expect(packet.toString('hex')).toContain(Buffer.from('1.3.6.1.4.1.1466.20037').toString('hex'));
});
```

Run:

```bash
cd backend
bun test -- ldap-message.spec.ts
```

Expected: FAIL because `encodeStartTlsRequest` does not exist.

- [ ] **Step 2: Add TLS client tests with injected sockets**

Refactor `TcpLdapClient` constructor to accept optional factories:

```ts
export interface TcpLdapClientFactories {
  connectTcp?: typeof connect;
  connectTls?: typeof tlsConnect;
}
```

Tests assert:

- `tlsMode='disabled'` uses TCP only.
- `tlsMode='ldaps'` uses TLS connect.
- `tlsMode='starttls'` sends StartTLS request before wrapping the socket.
- `verifyServerCertificate=true` passes `rejectUnauthorized: true`.

- [ ] **Step 3: Implement LDAP StartTLS encoder**

Add extended request support for OID `1.3.6.1.4.1.1466.20037`.

- [ ] **Step 4: Implement TLS connection modes**

`TcpLdapClient.connect()` accepts:

```ts
tlsMode: 'disabled' | 'starttls' | 'ldaps';
verifyServerCertificate: boolean;
servername: string;
```

For `ldaps`, use `node:tls.connect`.

For `starttls`, connect TCP, send StartTLS, require success, then wrap the socket with TLS.

- [ ] **Step 5: Remove non-plain TLS rejection**

Delete the runtime rejection blocks in:

- `tcp-ldap-authenticator.ts`
- `tcp-ldap-directory.ts`

Both adapters pass TLS options from selected profile.

- [ ] **Step 6: Remove env fallback from profile-aware flows**

`IdentityGroupResolverService.resolve` accepts selected LDAP directory options from the resolved authentication profile. Env fallback remains only for bootstrap health checks that do not have profile context.

- [ ] **Step 7: Run LDAP tests**

Run:

```bash
cd backend
bun test -- ldap-message.spec.ts tcp-ldap-directory.spec.ts ldap-authentication-provider.service.spec.ts identity-group-resolver.service.spec.ts
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/src/infrastructure/adapters/ldap backend/src/application/ports backend/src/application/services
git commit -m "feat(identity): support ldap tls and profile scoped groups"
```

---

## Task 7: Add Authentication Sequences and Allow Lists

**Files:**

- Create: `backend/src/application/services/authentication-sequence-resolver.service.ts`
- Test: `backend/src/application/services/authentication-sequence-resolver.service.spec.ts`
- Modify: `backend/src/application/services/authentication-engine.service.ts`
- Modify: `backend/src/application/services/authentication-profile-resolver.service.ts`
- Modify: `backend/src/application/dtos/authentication-engine.dto.ts`
- Modify: `backend/src/domain/entities/identity-settings.entity.ts`
- Modify: `backend/src/presentation/dtos/identity-config-profile.dto.ts`
- Modify: `backend/src/presentation/mappers/identity-config-response.mapper.ts`

- [ ] **Step 1: Add sequence evaluation tests**

Create `authentication-sequence-resolver.service.spec.ts` with cases:

- first profile timeout, second accepts,
- first profile rejects and `exitOnReject=true`, second is not called,
- first profile rejects and `exitOnReject=false`, second accepts,
- first profile allow-list miss, second accepts,
- all profiles unavailable returns `unavailable`.

Run:

```bash
cd backend
bun test -- authentication-sequence-resolver.service.spec.ts
```

Expected: FAIL because service does not exist.

- [ ] **Step 2: Extend auth target DTOs**

Represent portal/admin auth target as:

```ts
export type IdentityAuthenticationTarget =
  | { kind: 'profile'; id: string }
  | { kind: 'sequence'; id: string };
```

Settings keep backwards compatibility by mapping old string IDs to `{ kind: 'profile', id }`.

- [ ] **Step 3: Implement sequence resolver**

`AuthenticationSequenceResolverService.authenticate` accepts flow, username, password, and source IP. It resolves the target, then delegates to `AuthenticationEngineService.authenticateProfile`.

The existing provider dispatch becomes profile-level; sequence orchestration sits above it.

- [ ] **Step 4: Implement allow-list check**

After provider accepts credentials and groups are resolved, evaluate:

- username exact match,
- group exact match,
- `includeAllAuthenticated`.

If none match, return `allow_list_miss` with provider/profile IDs.

- [ ] **Step 5: Wire portal and admin flows**

`AuthenticateIdentityUseCase` and `LoginUserUseCase` call the new sequence resolver through `AuthenticationEngineService.authenticate`.

- [ ] **Step 6: Run auth tests**

Run:

```bash
cd backend
bun test -- authentication-engine.service.spec.ts authentication-profile-resolver.service.spec.ts authenticate-identity.use-case.spec.ts login-user.use-case.spec.ts authentication-sequence-resolver.service.spec.ts
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src/application backend/src/domain/entities/identity-settings.entity.ts backend/src/presentation
git commit -m "feat(identity): add authentication sequences"
```

---

## Task 8: Add Identity Group Catalog and Rule Reference Integrity

**Files:**

- Create: `backend/src/application/services/identity-group-catalog.service.ts`
- Create: `backend/src/application/services/identity-group-catalog.service.spec.ts`
- Create: `backend/src/presentation/controllers/identity-groups.controller.ts`
- Create: `backend/src/presentation/controllers/identity-groups.controller.spec.ts`
- Modify: `backend/src/application/services/identity-group-resolver.service.ts`
- Modify: `backend/src/application/services/identity-config-mutation.service.ts`
- Modify: `backend/src/modules/identity.module.ts`
- Modify: `backend/src/infrastructure/persistence/mappers/identity-config-json.mapper.ts`
- Modify: `backend/src/infrastructure/adapters/grpc-config-snapshot-push.service.ts`

- [ ] **Step 1: Add group catalog tests**

Test:

- local group adds username member,
- LDAP group is registered without local members,
- effective groups merge LDAP groups and local groups,
- duplicate group names reject,
- delete group referenced by active rule returns `IdentityProfileInUseException`.

Use rule content:

```text
match identity_group { = "Guests" : verdict drop }
```

Run:

```bash
cd backend
bun test -- identity-group-catalog.service.spec.ts
```

Expected: FAIL because service does not exist.

- [ ] **Step 2: Implement rule reference scanner**

Use existing RaptorLang content stored in backend rules. The scanner only needs exact `identity_group` string matches. It must return rule IDs and names for error responses.

- [ ] **Step 3: Merge local groups during group resolution**

`IdentityGroupResolverService` returns LDAP/VSA groups plus local group names whose members match the accepted username or external ID.

- [ ] **Step 4: Add controller endpoints**

Expose:

- `GET /identity/groups`
- `POST /identity/groups`
- `PUT /identity/groups/:id`
- `DELETE /identity/groups/:id`
- `POST /identity/groups/sync-ldap`

All write operations persist through `IdentityConfiguration`.

- [ ] **Step 5: Include non-secret groups in active identity catalog**

`mapIdentityPolicyCatalog` emits group IDs/names/source, not provider configuration.

- [ ] **Step 6: Run group tests**

Run:

```bash
cd backend
bun test -- identity-group-catalog.service.spec.ts identity-groups.controller.spec.ts identity-group-resolver.service.spec.ts grpc-config-snapshot-push.service.spec.ts
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src/application/services/identity-group-catalog.service.ts backend/src/presentation/controllers/identity-groups.controller.ts backend/src/modules backend/src/infrastructure
git commit -m "feat(identity): add identity group catalog"
```

---

## Task 9: Fix Admin Authorization for RADIUS and LDAP

**Files:**

- Modify: `backend/src/application/services/admin-authorization.service.ts`
- Modify: `backend/src/application/use-cases/login-user.use-case.ts`
- Modify: `backend/src/domain/entities/identity-authentication-profile.entity.ts`
- Test: `backend/src/application/services/admin-authorization.service.spec.ts`
- Test: `backend/src/application/use-cases/login-user.use-case.spec.ts`

- [ ] **Step 1: Add failing admin LDAP mapping test**

In `login-user.use-case.spec.ts`, create an external LDAP accept result:

```ts
{
  kind: 'accept',
  provider: 'ldap',
  username: 'alice',
  groups: ['admins'],
  groupSource: 'ldap',
  externalId: 'uid=alice,ou=users,dc=raptorgate,dc=local',
  sessionTtlSeconds: 3600,
  nasIp: '127.0.0.1',
  calledStationId: 'ldap',
  profileId: 'admin-ldap',
}
```

Expected login succeeds with role from `adminRoleMappings` and does not require a pre-existing local user when profile authorization mode is external mapping.

- [ ] **Step 2: Add authorization mode**

Add to authentication profile:

```ts
adminAuthorizationMode: 'local_admin_reference' | 'external_role_mapping'
```

Default legacy LDAP behavior maps to `local_admin_reference`. RADIUS external admin profiles use `external_role_mapping`.

- [ ] **Step 3: Update login use case**

For external accepted auth:

- if mode is `local_admin_reference`, require local user and complete local login,
- if mode is `external_role_mapping`, call `AdminAuthorizationService` for RADIUS and LDAP.

- [ ] **Step 4: Keep break-glass priority**

Local user with valid local password still wins before external auth.

- [ ] **Step 5: Run admin auth tests**

Run:

```bash
cd backend
bun test -- admin-authorization.service.spec.ts login-user.use-case.spec.ts identity-authentication-profile.entity.spec.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src/application backend/src/domain/entities/identity-authentication-profile.entity.ts
git commit -m "feat(identity): support external ldap admin role mappings"
```

---

## Task 10: Replace Fake MAC With Endpoint Binding

**Files:**

- Create: `backend/src/domain/value-objects/mac-address.vo.ts`
- Create: `backend/src/application/ports/firewall-endpoint-identity-query-service.interface.ts`
- Create: `backend/src/infrastructure/adapters/grpc-firewall-endpoint-identity-query.service.ts`
- Create: `crates/raptorgate/src/identity/endpoint.rs`
- Modify: `proto/services/identity_session_service.proto`
- Modify: `proto/services/query_service.proto`
- Modify: `backend/src/domain/entities/identity-session.entity.ts`
- Modify: `backend/src/application/use-cases/authenticate-identity.use-case.ts`
- Modify: `backend/src/infrastructure/persistence/schemas/identity-sessions.schema.ts`
- Modify: `backend/src/infrastructure/persistence/mappers/identity-session-json.mapper.ts`
- Modify: `backend/src/infrastructure/adapters/grpc-identity-session-sync.service.ts`
- Modify: `crates/raptorgate/src/identity/session.rs`
- Modify: `crates/raptorgate/src/identity/store.rs`
- Modify: `crates/raptorgate/src/identity/enforcement.rs`
- Modify: `crates/raptorgate/src/pipeline/wrappers.rs`
- Modify: `crates/raptorgate/src/query_server.rs`

- [ ] **Step 1: Add failing backend test**

In `authenticate-identity.use-case.spec.ts`, assert:

```ts
expect(sync.upsertedSession().macAddress).not.toBe('00:00:00:00:00:00');
expect(sync.upsertedSession().endpointBindingStatus).toBe('mac_resolved');
```

Also add a second test where the endpoint query returns not found:

```ts
expect(sync.upsertedSession().macAddress).toBeNull();
expect(sync.upsertedSession().endpointBindingStatus).toBe('mac_unresolved');
```

- [ ] **Step 2: Add proto fields**

Update `IdentityManagerUserSession`:

```proto
optional string mac_address = 4;
string endpoint_binding_status = 11;
string auth_provider = 12;
string auth_profile_id = 13;
string auth_sequence_id = 14;
string group_source = 15;
google.protobuf.Timestamp last_seen_at = 16;
```

Keep existing field numbers.

- [ ] **Step 3: Add backend endpoint query port**

The port returns:

```ts
export type EndpointIdentityLookup =
  | { kind: 'found'; ipAddress: string; macAddress: string }
  | { kind: 'not_found'; ipAddress: string }
  | { kind: 'unavailable'; message: string };
```

- [ ] **Step 4: Add firewall query RPC**

Extend `FirewallQueryService` in `proto/services/query_service.proto`:

```proto
rpc ResolveEndpointIdentity(ResolveEndpointIdentityRequest)
    returns (ResolveEndpointIdentityResponse);

message ResolveEndpointIdentityRequest {
  string ip_address = 1;
}

message ResolveEndpointIdentityResponse {
  bool found = 1;
  string ip_address = 2;
  optional string mac_address = 3;
  string source = 4;
}
```

Rust `query_server.rs` reads the local neighbor/session view and returns `found=false` when no MAC is known for the IP.

- [ ] **Step 5: Remove placeholder MAC**

Delete `PLACEHOLDER_MAC` from `authenticate-identity.use-case.ts`. The use case queries endpoint identity by source IP before upsert. It stores null MAC if unresolved and records status.

- [ ] **Step 6: Update Rust session model**

Rust `IdentitySession` stores:

```rust
pub mac_address: Option<MacAddress>,
pub endpoint_binding_status: EndpointBindingStatus,
pub auth_provider: String,
pub auth_profile_id: String,
pub auth_sequence_id: Option<String>,
pub group_source: String,
pub last_seen_at: SystemTime,
```

`MacAddress` validation rejects invalid strings and all-zero addresses.

- [ ] **Step 7: Validate MAC on packet when available**

`resolve_identity` keeps current IP lookup but checks MAC when `PacketContext` has source Ethernet metadata and the session has a MAC. Mismatch returns `AuthState::Unknown`.

- [ ] **Step 8: Generate proto and run tests**

Run:

```bash
cd backend
bun run proto:generate
```

Run:

```bash
cd backend
bun test -- authenticate-identity.use-case.spec.ts identity-session.entity.spec.ts json-identity-session.store.spec.ts
```

Run:

```bash
cargo test -p ngfw identity::
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add proto backend/src crates/raptorgate/src/identity crates/raptorgate/src/pipeline/wrappers.rs crates/raptorgate/src/query_server.rs
git commit -m "feat(identity): bind sessions to endpoint metadata"
```

---

## Task 11: Make Portal Enforcement Production-Grade

**Files:**

- Modify: `backend/src/domain/entities/identity-settings.entity.ts`
- Modify: `backend/src/application/use-cases/update-identity-settings.use-case.ts`
- Modify: `backend/src/presentation/controllers/identity.controller.ts`
- Modify: `backend/src/presentation/dtos/identity-login-response.dto.ts`
- Modify: `frontend/src/pages/PortalPage.tsx`
- Modify: `frontend/src/services/portal.ts`
- Modify: `vagrant/deploy.sh`
- Modify: `docs/adr/0004-captive-portal-mvp.md`
- Test: `backend/src/domain/entities/identity-settings.entity.spec.ts`
- Test: `backend/src/application/use-cases/update-identity-settings.use-case.spec.ts`
- Test: `backend/src/presentation/controllers/identity.controller.spec.ts`

- [ ] **Step 1: Add settings tests**

Test that production portal settings require:

- enabled listener,
- bind address,
- bind port,
- redirect host,
- auth target,
- idle timeout lower than max TTL.

Run:

```bash
cd backend
bun test -- identity-settings.entity.spec.ts update-identity-settings.use-case.spec.ts
```

Expected: FAIL until settings are extended.

- [ ] **Step 2: Extend portal settings**

Add fields:

```ts
mode: 'redirect';
redirectHost: string;
idleTimeoutSeconds: number;
maxTtlSeconds: number;
trustedProxyCidrs: string[];
tlsServiceProfileRef: string | null;
```

Transparent mode is not accepted by DTO validation in this plan.

- [ ] **Step 3: Harden source IP trust boundary**

`IdentityController.resolveSourceIp` uses `X-Forwarded-For` only when the immediate peer is in `trustedProxyCidrs`. Body source IP remains ignored.

- [ ] **Step 4: Generate runtime portal listener config**

`vagrant/deploy.sh` renders nginx portal listener from persisted identity settings or documented seed defaults. The generated vhost must not expose admin API routes on the portal listener.

- [ ] **Step 5: Update ADR 0004**

Change status to superseded by this production portal design. Keep the old manual-URL behavior documented as historical MVP.

- [ ] **Step 6: Run portal tests**

Run:

```bash
cd backend
bun test -- identity-settings.entity.spec.ts update-identity-settings.use-case.spec.ts identity.controller.spec.ts
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/src frontend/src/pages/PortalPage.tsx frontend/src/services/portal.ts vagrant/deploy.sh docs/adr/0004-captive-portal-mvp.md
git commit -m "feat(identity): make portal listener production configured"
```

---

## Task 12: Add Per-User Identity Activity

**Files:**

- Create: `crates/raptorgate/src/identity/activity.rs`
- Create: `backend/src/application/services/identity-activity-aggregator.service.ts`
- Create: `backend/src/application/services/identity-activity-aggregator.service.spec.ts`
- Create: `backend/src/presentation/controllers/identity-activity.controller.ts`
- Create: `backend/src/presentation/controllers/identity-activity.controller.spec.ts`
- Modify: `crates/raptorgate/src/events.rs`
- Modify: `crates/raptorgate/src/pipeline/wrappers.rs`
- Modify: `backend/src/modules/identity.module.ts`
- Modify: `frontend/src/pages/Identity.tsx`

- [ ] **Step 1: Add aggregator tests**

Test aggregation by username:

```ts
expect(result.users[0]).toMatchObject({
  username: 'alice',
  applications: ['http', 'dns'],
  destinationIps: ['192.168.20.10'],
  bytesClientToServer: 1200,
  bytesServerToClient: 3400,
  allowedCount: 2,
  blockedCount: 1,
});
```

Run:

```bash
cd backend
bun test -- identity-activity-aggregator.service.spec.ts
```

Expected: FAIL because aggregator does not exist.

- [ ] **Step 2: Emit firewall identity activity event**

When policy verdict is known, build an event with:

- session id,
- username,
- groups,
- source IP,
- MAC when available,
- app proto,
- destination IP/domain,
- byte counters,
- verdict,
- rule id.

- [ ] **Step 3: Aggregate in backend**

The backend stores rolling in-memory aggregates first and exposes a deterministic API. Persistence can use the existing event sink if already configured in the branch.

- [ ] **Step 4: Add frontend view**

Identity page gets an Activity tab showing:

- username,
- current groups,
- applications,
- destinations,
- bytes,
- last seen,
- blocked/allowed counts.

- [ ] **Step 5: Run activity tests**

Run:

```bash
cd backend
bun test -- identity-activity-aggregator.service.spec.ts identity-activity.controller.spec.ts
```

Run:

```bash
cargo test -p ngfw identity::activity
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/src crates/raptorgate/src frontend/src/pages/Identity.tsx
git commit -m "feat(identity): aggregate per-user activity"
```

---

## Task 13: Update Frontend Identity Management

**Files:**

- Modify: `frontend/src/types/identity/IdentityConfig.ts`
- Modify: `frontend/src/types/identity/IdentitySession.ts`
- Modify: `frontend/src/services/identityConfig.ts`
- Modify: `frontend/src/services/identitySessions.ts`
- Modify: `frontend/src/pages/Identity.tsx`
- Modify: `docs/identity-frontend-manual-tests.md`

- [ ] **Step 1: Update frontend types**

Types must include:

- RADIUS server endpoint list,
- LDAP server endpoint list,
- authentication sequences,
- identity groups,
- portal production listener fields,
- endpoint binding status on sessions.

- [ ] **Step 2: Update RTK Query services**

Add endpoints for:

- identity groups,
- authentication sequences,
- activity aggregates.

- [ ] **Step 3: Update Identity page**

Keep the existing dense operations layout. Add tabs or sections for:

- RADIUS endpoints inside a profile,
- LDAP endpoints and TLS verification,
- Authentication Sequences,
- Groups,
- Activity,
- Diagnostics.

- [ ] **Step 4: Update manual frontend tests**

Replace MVP wording with production checks:

- multi-server profile CRUD,
- TLS mode validation,
- auth sequence fallback,
- local group deletion blocked when referenced,
- session MAC status visible,
- per-user activity visible.

- [ ] **Step 5: Build frontend**

Run:

```bash
cd frontend
npm run build
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add frontend/src docs/identity-frontend-manual-tests.md
git commit -m "feat(identity): expose production identity controls"
```

---

## Task 14: Update Manual and Lab Verification

**Files:**

- Modify: `docs/identity-radius-manual-tests.md`
- Modify: `docs/identity-frontend-manual-tests.md`
- Modify: `vagrant/`

- [ ] **Step 1: Rename MVP manual test document title**

Change:

```markdown
# Manualne testy identity/RADIUS MVP
```

to:

```markdown
# Manualne testy produkcyjnego Identity/RADIUS/LDAP
```

- [ ] **Step 2: Remove global allow-all acceptance**

Keep warnings that `DEV_OVERRIDE_POLICY=allow-all` invalidates tests. Add a hard precheck:

```bash
test "$(grep -E '^DEV_OVERRIDE_POLICY=' /etc/systemd/system/ngfw.env | cut -d= -f2)" != "allow-all"
```

Expected: command exits `0`.

- [ ] **Step 3: Add production verification cases**

Add manual cases:

- RADIUS endpoint failover: first endpoint down, second endpoint accepts.
- LDAP LDAPS: certificate valid succeeds.
- LDAP certificate invalid: auth/group test fails closed.
- Authentication sequence: RADIUS timeout falls back to LDAP.
- Local group: user receives group without LDAP membership.
- Group deletion blocked while active rule references it.
- Portal source IP cannot be supplied in body.
- Session has real MAC or `mac_unresolved`, never all-zero.
- Per-user activity updates after HTTP and DNS traffic.

- [ ] **Step 4: Run lab smoke**

Run:

```bash
cd vagrant
vagrant status
```

Run:

```bash
cd vagrant
vagrant provision radius ldap h2 r1
```

Run the documented manual ID checks for portal login, group policy, logout, RADIUS timeout, LDAP refresh, admin login, and activity.

- [ ] **Step 5: Commit**

```bash
git add docs vagrant
git commit -m "docs(identity): update production identity verification"
```

---

## Task 15: Full Verification Gate

**Files:**

- No source files unless failures reveal defects in files touched by earlier tasks.

- [ ] **Step 1: Backend unit tests**

Run:

```bash
cd backend
bun test -- identity
```

Expected: PASS.

- [ ] **Step 2: Backend full test suite**

Run:

```bash
cd backend
bun test
```

Expected: PASS.

- [ ] **Step 3: Backend build**

Run:

```bash
cd backend
bun run build
```

Expected: PASS.

- [ ] **Step 4: Rust identity and policy tests**

Run:

```bash
cargo test -p ngfw identity:: policy::policy_evaluator rule_tree::parsing::lower
```

Expected: PASS.

- [ ] **Step 5: Rust full crate tests**

Run:

```bash
cargo test -p ngfw
```

Expected: PASS.

- [ ] **Step 6: Frontend build**

Run:

```bash
cd frontend
npm run build
```

Expected: PASS.

- [ ] **Step 7: Config import/export smoke**

Export config, import it, diff it, and rollback from the UI/API. Expected:

- identity config survives round trip,
- active firewall push carries no provider secrets,
- identity runtime sessions are not serialized into durable config snapshot.

- [ ] **Step 8: Final commit**

```bash
git status --short
git add backend frontend crates/raptorgate proto docs vagrant
git commit -m "feat(identity): complete production radius ldap identity"
```

---

## Self-Review Checklist

- Every PDF F9 requirement maps to at least one task.
- Provider secrets remain backend-only.
- The firewall still receives sessions over `IdentitySessionService`.
- Unsupported RADIUS protocols are not exposed as working config.
- LDAP TLS modes are runtime behavior, not only stored fields.
- No fake MAC address is created.
- Authentication sequences work for portal and admin flows.
- Group deletion checks active rule references.
- Manual docs no longer call the accepted flow MVP.
