# Production Identity, RADIUS, and LDAP Design

## Goal

Build identity as a production control-plane feature for RaptorGate: RADIUS and LDAP provider configuration, authentication profiles, authentication sequences, group mapping, portal authentication, admin authorization, runtime user sessions, firewall enforcement, diagnostics, and per-user activity must form one coherent system.

This design replaces the old "Issue A — First-Class Identity Configuration" plan as the target for RADIUS/LDAP completion. Issue A is useful historical context, but it only covered configuration scaffolding and explicitly excluded runtime authentication, admin mapping, frontend, diagnostics, and policy cleanup.

The target is Palo Alto-inspired behavior, not a clone of every PAN-OS feature. RaptorGate must be honest about supported protocols and must not expose settings that the runtime cannot enforce.

## Inputs

Project PDF requirements:

- F9.1: maintain current user, endpoint device, and IP mapping for policy enforcement.
- F9.2: integrate with RADIUS for user authentication.
- F9.3: manage groups from Active Directory or local definitions.
- F9.4: attach RADIUS identity to packet context and rule engine.
- F9.5: aggregate activity per user: applications, destination IPs/domains, and traffic volume.
- F9.6: match rules by user identity and group.
- UC-10: RADIUS auth creates user/IP/MAC mapping; packets are enriched with identity; policy sees user/group; RADIUS failure uses a configured fallback policy; unknown IP continues without identity context.
- UC-17: administrators manage groups, assign users manually or from AD sync, rules reference groups, changes affect policy immediately, operations are audited, AD sync errors are visible, and deleting groups used by active rules is blocked.

Existing project decisions:

- ADR 0001 remains authoritative: backend is the identity control plane; firewall is data-plane enforcement. Firewall must not talk to RADIUS/LDAP and must not receive provider secrets.
- ADR 0002 and ADR 0003 remain authoritative: identity sessions are runtime state, synced through `IdentitySessionService`, not durable config snapshots.
- ADR 0005 is refined by this design: LDAP remains the primary group source, RADIUS VSA is a fallback, and local groups become a first-class group source required by UC-17.

Palo Alto references used for behavior shape:

- RADIUS server profiles support ordered servers, timeout/retries, authentication protocol, and certificate profile for EAP methods.
- LDAP server profiles support ordered servers, server type, base DN, SSL/TLS, server certificate verification, timeout, and retry interval.
- Authentication sequences try one or more authentication profiles in order and can stop on failed credentials while continuing on timeout or allow-list miss.
- Group mapping retrieves users/groups from LDAP and uses update intervals.
- Authentication Portal is enforced through authentication policy, has redirect/transparent modes, timers, authentication profile, and TLS service profile.
- RADIUS VSAs include separate Palo Alto attributes for admin role and user group; these must not be collapsed into one generic "groups" list.

## Current State

The repository already contains more than the old Issue A plan:

- `backend/src/domain/entities/identity-configuration.entity.ts` aggregates RADIUS profiles, LDAP profiles, authentication profiles, and identity settings.
- `backend/src/infrastructure/persistence/repositories/json-identity-config.repository.ts` persists one `identity-config.json` aggregate.
- `backend/src/presentation/controllers/identity-config.controller.ts` exposes identity configuration endpoints.
- `backend/src/application/services/authentication-engine.service.ts` dispatches portal/admin auth to local, RADIUS, or LDAP providers.
- `backend/src/infrastructure/adapters/radius/radius-packet.ts` builds and parses RADIUS PAP packets.
- `backend/src/infrastructure/adapters/ldap/tcp-ldap-client.ts` implements a minimal LDAPv3 TCP client.
- `backend/src/application/use-cases/authenticate-identity.use-case.ts` creates identity sessions and syncs them to the firewall.
- `proto/services/identity_session_service.proto` defines runtime session sync.
- `crates/raptorgate/src/identity/` stores sessions and enriches packet policy context.
- `crates/raptorgate/src/policy/policy_evaluator.rs` already matches `auth_state`, `identity_user`, and `identity_group`.

The current gaps are production blockers:

- RADIUS profile is one server, PAP-only, and collapses Palo Alto admin-role VSA and user-group VSA into one group list.
- LDAP profiles allow `starttls` and `ldaps`, but both runtime adapters reject non-plain TCP.
- LDAP group lookup still has env fallback and does not consistently use the selected authentication profile context.
- Authentication profiles do not support authentication sequences or allow-list semantics.
- LDAP admin login is gated by an existing local admin account and bypasses external role mappings.
- Identity sessions use `00:00:00:00:00:00` as a MAC placeholder.
- Portal listener config is persisted, but lab nginx remains static and manual-URL based.
- Manual docs still call the flow MVP and rely on SOCKS/PAC topology for correct source IP.
- Active config push currently drops identity data with `identity: undefined`, while durable config snapshots include `identity_config`.

## Architecture

Identity has three layers:

```text
Backend identity config and auth
  -> RADIUS/LDAP/local auth, group mapping, local groups, auth sequence, audit
  -> creates runtime identity session
  -> syncs session to firewall over IdentitySessionService

Firewall identity runtime
  -> stores active sessions by client IP with endpoint binding metadata
  -> enriches PacketContext before policy evaluation
  -> evaluates auth_state, identity_user, identity_group
  -> emits per-user activity events

Backend visibility and administration
  -> persists durable config, imports/exports snapshots, validates references
  -> exposes UI/API for profiles, groups, sequences, portal, sessions, diagnostics
  -> aggregates activity and audit logs
```

Provider secrets never leave backend. Firewall receives active sessions and optional non-secret identity policy catalog only if the data plane needs it for validation or observability.

Backend resolves endpoint metadata through the existing firewall query channel. The query is keyed by source IP and returns MAC metadata from the firewall's local neighbor/session view; it is not a RADIUS/LDAP provider query and does not violate ADR 0001.

## Configuration Model

`IdentityConfiguration` remains the aggregate root. It must be extended, not replaced by four separate repositories. Persistence stays in `backend/data/json-db/identity-config.json` through `JsonIdentityConfigRepository`.

The aggregate contains:

- `radiusServerProfiles`
- `ldapServerProfiles`
- `authenticationProfiles`
- `authenticationSequences`
- `identityGroups`
- `settings`

### RADIUS Server Profile

A RADIUS server profile represents one logical provider with ordered endpoints:

```text
RadiusServerProfile
  id
  name
  description
  isActive
  administratorUseOnly
  authenticationProtocol
  timeoutMs
  retries
  nasIp
  nasIdentifier
  calledStationId
  certificateProfileRef
  outerIdentity
  servers[]
  createdAt
  updatedAt
  createdBy
```

Each server endpoint contains:

```text
RadiusServerEndpoint
  id
  name
  host
  port
  sharedSecretRef
  priority
  isActive
```

Runtime support rules:

- A profile must have at least one active endpoint before it can be used by an active authentication profile.
- Endpoints are tried by ascending `priority`.
- Timeout/retry applies per endpoint.
- A reject is final for that profile.
- Timeout or transport error advances to the next endpoint.
- If all endpoints time out, the result is `timeout`.
- If all endpoints fail with transport/protocol errors, the result is `unavailable`.
- PAP must remain supported because the lab FreeRADIUS flow uses it.
- Any exposed `authenticationProtocol` value must have a real adapter path. Unsupported protocol values must be rejected by validation, not accepted as inert config.

RADIUS response attributes are parsed into typed fields:

```text
RadiusAttributeResult
  userGroups[]
  adminRole
  accessDomain
  panoramaAdminRole
  panoramaAccessDomain
  userDomain
  rawDiagnostics[]
```

Palo Alto VSA `PaloAlto-Admin-Role` is for admin authorization. `PaloAlto-User-Group` is for group membership. They must not be mixed.

### LDAP Server Profile

An LDAP server profile represents one directory profile with ordered endpoints and mapping rules:

```text
LdapServerProfile
  id
  name
  description
  isActive
  serverType
  baseDn
  bindDn
  bindPasswordRef
  tlsMode
  verifyServerCertificate
  certificateProfileRef
  connectTimeoutMs
  searchTimeoutMs
  retryIntervalSeconds
  userSearch
  groupMapping
  servers[]
  cacheTtlSeconds
  createdAt
  updatedAt
  createdBy
```

Each LDAP endpoint contains:

```text
LdapServerEndpoint
  id
  name
  host
  port
  priority
  isActive
```

TLS modes:

- `disabled`: plain LDAP over TCP.
- `starttls`: LDAP StartTLS extended operation, then TLS, then bind/search.
- `ldaps`: TLS from connect.

`verifyServerCertificate=true` requires a configured trust source and must fail closed when the certificate is invalid. `verifyServerCertificate=false` is allowed only with an explicit insecure flag in diagnostics and audit.

LDAP group mapping contains:

```text
LdapGroupMapping
  userBaseDn
  userFilterAttribute
  userNameAttribute
  groupBaseDn
  groupMemberAttribute
  groupNameAttribute
  includeGroups[]
  updateIntervalSeconds
```

Group refresh must use the authentication profile's LDAP profile, not env fallback, whenever the session records the profile context.

### Authentication Profile

An authentication profile binds a flow to one provider:

```text
IdentityAuthenticationProfile
  id
  name
  description
  isActive
  provider
  radiusProfileId
  ldapProfileId
  groupSource
  allowList
  usernameModifier
  sessionTtlSeconds
  adminRoleMappings[]
  createdAt
  updatedAt
  createdBy
```

Provider rules:

- `radius` requires `radiusProfileId`.
- `ldap` requires `ldapProfileId`.
- `local` cannot reference RADIUS or LDAP.
- `groupSource=ldap` requires `ldapProfileId`.
- `groupSource=radius_vsa` requires `provider=radius`.
- `groupSource=none` returns no external groups but still can merge local groups.

Allow list:

```text
AuthenticationAllowList
  users[]
  groups[]
  includeAllAuthenticated
```

Allow-list miss is not the same as credential reject. In an authentication sequence, allow-list miss advances to the next profile unless `exitOnReject` explicitly covers it.

### Authentication Sequence

An authentication sequence is an ordered list of active authentication profiles:

```text
IdentityAuthenticationSequence
  id
  name
  description
  isActive
  profileIds[]
  exitOnReject
  useDomainRouting
  createdAt
  updatedAt
  createdBy
```

Evaluation:

- Profiles are tried in order unless domain routing picks a matching profile.
- `accept` stops the sequence.
- `reject` stops if `exitOnReject=true`; otherwise it advances.
- `timeout`, `unavailable`, `disabled`, `misconfigured`, and allow-list miss advance to the next profile.
- If all profiles fail, the final result exposes the strongest reason in this order: `reject`, `timeout`, `unavailable`, `misconfigured`, `disabled`, `allow_list_miss`.

### Identity Groups

Identity groups are first-class objects for UC-17:

```text
IdentityGroup
  id
  name
  description
  source
  externalDn
  members[]
  createdAt
  updatedAt
  createdBy
```

Sources:

- `local`: defined and managed in RaptorGate.
- `ldap`: discovered from LDAP group mapping and optionally pinned in the include list.
- `radius_vsa`: discovered from RADIUS response attributes.

Local membership contains usernames or external IDs:

```text
IdentityGroupMember
  principal
  principalType
```

The effective session groups are the union of:

- LDAP groups when `groupSource=ldap`.
- RADIUS user groups when `groupSource=radius_vsa`.
- Local groups whose membership matches the accepted username or external ID.

Deletion of an identity group is blocked when any active rule references that group by name.

## Runtime Session Model

The backend creates runtime identity sessions after successful portal authentication. Session data must be concrete and must not use fake placeholders.

```text
IdentitySession
  sessionId
  identityUserId
  username
  sourceIp
  macAddress
  endpointBindingStatus
  authProvider
  authProfileId
  authSequenceId
  groupSource
  groups[]
  nasIp
  calledStationId
  authenticatedAt
  expiresAt
  lastSeenAt
```

`macAddress` is optional at the transport boundary but cannot be filled with `00:00:00:00:00:00`. If MAC cannot be resolved, `endpointBindingStatus=mac_unresolved` is stored and diagnostics must show it.

Firewall lookup remains keyed by client IP for hot path efficiency. When `macAddress` is present and packet source MAC is available, the firewall validates the MAC binding. A mismatch makes the packet identity `unknown` and emits an audit/diagnostic event.

Session renewal and group refresh are idempotent upserts with the same `sessionId`.

## Portal Enforcement

Manual URL portal remains allowed as an admin-visible direct login path, but it is not enough for production acceptance.

Production portal behavior:

- Identity settings define portal mode, listener interface/zone/bind address/bind port, redirect host, idle timeout, max TTL, TLS service profile reference, and authentication target.
- The portal must be reachable only through the configured listener surface.
- Backend trusts `X-Forwarded-For` only from configured local/trusted reverse proxy addresses.
- Login request body cannot override source IP.
- Portal authentication target can point to either an authentication profile or an authentication sequence.
- Pre-auth policy must not rely on a global allow-all override.
- A user without identity can reach the portal and allowed bootstrap destinations only.
- After successful login, backend syncs session to firewall and new traffic is evaluated with identity context.
- Logout revokes the backend session and firewall runtime session.

Redirect mode is the production default. Transparent mode is not exposed until the TLS/application pipeline can enforce it without browser certificate failures.

## Policy Enforcement

Firewall policy must keep matching:

- `auth_state = authenticated|unknown`
- `identity_user = "username"`
- `identity_group = "group-name"`

Identity lookup happens before policy evaluation and before NAT can hide original source identity. Unknown identity is not an error; rules that require identity simply do not match.

RADIUS or LDAP unavailability affects authentication attempts, not already-authenticated sessions. Existing sessions remain valid until expiry unless explicitly revoked or refreshed into a denied state.

Default fallback for an unauthenticated/unknown user is controlled by ordinary rules. The seed config must use explicit identity pre-auth rules instead of `DEV_OVERRIDE_POLICY=allow-all`.

## Activity and Visibility

The firewall emits per-flow identity context in activity events:

```text
IdentityActivityEvent
  sessionId
  username
  identityUserId
  groups[]
  sourceIp
  macAddress
  appProto
  destinationIp
  destinationDomain
  bytesClientToServer
  bytesServerToClient
  verdict
  ruleId
  observedAt
```

Backend aggregates activity by user/session over configurable windows for the Identity dashboard:

- applications used,
- destination IPs,
- destination domains,
- bytes sent/received,
- blocked/allowed verdict counts,
- last seen timestamp.

## Config Snapshot Boundary

Durable backend snapshots include `identity_config` so import/export/diff/rollback remain complete.

Active firewall config push must not include provider secrets or provider connection details. The active gRPC bundle either:

- sends no identity provider config and relies only on runtime sessions, or
- sends a non-secret `IdentityPolicyCatalog` containing group/user names used for diagnostics.

The implementation must choose one path and make it explicit in proto, mapper tests, and docs. `identity: undefined` is not acceptable because it hides an architectural decision.

## Error Handling

Errors are categorized by recovery:

- Credential reject: user-facing 401, no retry inside the same profile.
- Allow-list miss: user-facing 403, sequence may continue.
- Provider timeout: retry endpoint/profile according to config, final 503 if no profile accepts.
- Provider unavailable: try next endpoint/profile, final 503 with diagnostic ID.
- Provider misconfigured: fail fast for that profile, show admin-facing diagnostic.
- LDAP group lookup failure after accepted RADIUS auth: use configured fallback, log diagnostic, and mark session `groupSource=radius_vsa` or `none`.
- MAC unresolved: create session only if policy permits `mac_unresolved`; always audit.
- MAC mismatch: packet identity becomes unknown; session remains until explicit revocation or expiry.

All external auth attempts and group changes emit audit events.

## API and UI Requirements

Backend API must expose:

- RADIUS profiles with ordered server endpoints and test endpoint.
- LDAP profiles with ordered server endpoints, TLS/cert settings, and test endpoint.
- Authentication profiles.
- Authentication sequences.
- Identity groups with local membership and LDAP sync diagnostics.
- Identity settings for portal/admin auth target and portal listener.
- Active sessions list/revoke/refresh.
- Identity diagnostics for provider status, last auth attempts, group refresh, MAC binding, and firewall sync.
- Per-user activity aggregates.

Frontend Identity must expose the same model without hidden lab-only assumptions. Manual test docs must stop calling the flow MVP after acceptance criteria pass.

## Acceptance Criteria

Production identity is complete when:

- Import/export/apply/rollback preserves the entire durable identity config.
- Active firewall push has an explicit identity boundary and never carries RADIUS shared secrets or LDAP bind passwords.
- RADIUS profile can use multiple active endpoints in priority order.
- RADIUS rejects, timeouts, transport errors, and invalid authenticators produce distinct outcomes.
- RADIUS attributes distinguish Palo Alto admin role from user group.
- LDAP `disabled`, `starttls`, and `ldaps` modes behave according to config.
- LDAP certificate verification can fail closed.
- LDAP group refresh uses the session's configured LDAP profile, not env fallback.
- Authentication sequence fallback works for portal and admin flows.
- Allow-list miss is distinguishable from credential reject.
- LDAP and RADIUS admin authorization use explicit role mappings unless a local-admin-reference mode is selected.
- Local groups can be created, assigned, referenced by rules, and protected from deletion while in active use.
- Portal no longer depends on manual URL plus static lab-only nginx for production acceptance.
- Backend never accepts source IP from login body.
- Sessions do not contain fake MAC addresses.
- Firewall packet context contains identity before policy evaluation.
- Unknown IP traffic is processed as unknown identity and only network/non-identity rules can match.
- Identity rules for user/group pass Rust policy tests and lab smoke tests.
- Per-user activity is visible in backend API and frontend.
- Audit logs cover auth success/failure, provider errors, group changes, session create/revoke, and blocked group deletion.
