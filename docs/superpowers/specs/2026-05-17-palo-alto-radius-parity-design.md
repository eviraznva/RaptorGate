# Palo Alto-Style RADIUS Authentication and Authorization Design

## Goal

Make RaptorGate RADIUS identity behavior match Palo Alto PAN-OS semantics closely enough that an administrator can reason about RADIUS server profiles, authentication profiles, administrator authorization, authentication policy, Authentication Portal sessions, and User-ID policy enforcement the same way they would on a Palo Alto firewall.

This is not an MVP target. The implementation must be real, interoperable, and testable against normal RADIUS servers. Work may be delivered in separate implementation phases, but each phase must preserve a coherent production behavior and must not fake Palo Alto compatibility.

## Sources

This design is based on current RaptorGate code and official Palo Alto documentation:

- Palo Alto RADIUS authentication and VSA semantics: https://docs.paloaltonetworks.com/ngfw/administration/authentication/authentication-types/radius
- Palo Alto RADIUS configuration flow, protocol choices, multi-server behavior, and Allow List behavior: https://docs.paloaltonetworks.com/ngfw/administration/authentication/configure-radius-authentication
- Palo Alto RADIUS server profile fields: https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-web-interface-help/device/device-server-profiles-radius
- Palo Alto Authentication Profile fields and the rule that RADIUS groups from VSA are for Allow List matching, not policy or reporting: https://docs.paloaltonetworks.com/ngfw/help/10-2/device/device-authentication-profile/configure-an-authentication-profile
- Palo Alto Authentication Policy and User-ID mapping behavior: https://docs.paloaltonetworks.com/ngfw/administration/authentication/authentication-policy
- Palo Alto Authentication Portal timers: https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-web-interface-help/user-identification/device-user-identification-captive-portal-settings
- Palo Alto Authentication Policy timestamps: https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/authentication/authentication-policy/authentication-timestamps

## Current Baseline

RaptorGate currently has a useful identity skeleton:

- Backend owns provider configuration, authenticates portal/admin users, creates identity sessions, and syncs them to the firewall over gRPC.
- Firewall stores runtime identity sessions keyed by client IP and evaluates `auth_state`, `identity_user`, and `identity_group`.
- RADIUS packet support is implemented directly in `backend/src/infrastructure/adapters/radius/radius-packet.ts`.
- RADIUS transport is UDP with retry and timeout in `UdpRadiusAuthenticator`.
- Authentication profiles can point to RADIUS, LDAP, or local providers.
- LDAP can resolve groups for policy, and RADIUS VSA can currently act as a group source.

The baseline diverges from PAN-OS in ways this design fixes:

- RADIUS supports only PAP.
- RADIUS server profile has one server instead of an ordered server list.
- PAN-OS RADIUS VSAs are flattened into one `groups` list.
- `PaloAlto-Admin-Role` and `PaloAlto-User-Group` are not semantically separated.
- RADIUS VSA groups can become policy groups, but PAN-OS uses those groups for Authentication Profile Allow List matching, not policy or reports.
- Authentication Profile has no Allow List, failed-attempt lockout, or real RADIUS group retrieval switch.
- Authentication Portal has only one TTL, while PAN-OS has an idle timer and a maximum timer.
- Authentication Policy is represented indirectly by seeded security rules, not a first-class authentication rulebase with timestamps.

## Non-Goals

This design does not clone Panorama device group/template administration.

This design does not implement GlobalProtect endpoint VSA forwarding unless a later VPN/GlobalProtect-equivalent feature needs it.

This design does not keep legacy RADIUS VSA-as-policy-groups semantics as the default. Legacy compatibility can be added as a migration flag, but the target behavior is PAN-OS-like.

This design does not move RADIUS or LDAP secrets into firewall data plane. Backend remains the identity control plane.

## Target Principles

RADIUS authentication and authorization must be separate decisions.

`Access-Accept` means credentials were accepted by the RADIUS server. It does not automatically mean the user is allowed by an Authentication Profile. The Authentication Profile must still evaluate Allow List, retrieved RADIUS user groups, lockout state, active status, and flow restrictions.

PAN-OS RADIUS VSAs must remain typed:

- `PaloAlto-Admin-Role` controls external administrator role authorization.
- `PaloAlto-Admin-Access-Domain` controls administrator access domain when virtual systems are modeled.
- `PaloAlto-User-Group` supplies group names for Authentication Profile Allow List matching.
- GlobalProtect endpoint VSAs are parsed but ignored by non-VPN flows until a VPN feature consumes them.

Security policy groups must come from User-ID group mapping, primarily LDAP or another directory source. RADIUS user group VSA must not be treated as security policy group membership.

Authentication Policy must be first-class. Traffic that matches an Authentication Policy rule must trigger Authentication Portal or MFA enforcement before Security Policy is evaluated as allowed.

## Architecture

The architecture remains control-plane/data-plane split:

- Backend stores and evaluates identity configuration.
- Backend speaks RADIUS and LDAP.
- Backend owns Authentication Profile, administrator authorization, Authentication Policy timestamps, lockout state, and portal session lifecycle.
- Firewall stores runtime User-ID mappings and authentication timestamps sent by backend.
- Firewall enforces packet-path decisions using runtime identity context and first-class Authentication Policy/Security Policy evaluation.

New or changed components:

- `RadiusClient` replaces the PAP-only `UdpRadiusAuthenticator` interface with a protocol-aware RADIUS client.
- `RadiusPacketCodec` parses and encodes RADIUS packet families and typed attributes.
- `RadiusEapClient` implements EAP-based RADIUS flows.
- `AuthenticationProfileEvaluator` evaluates active status, provider result, Allow List, retrieved RADIUS groups, and lockout.
- `AdminAuthorizationEvaluator` evaluates Palo Alto admin VSAs and local fallback mappings.
- `UserIdMappingService` turns successful end-user authentication into a User-ID runtime mapping.
- `AuthenticationPolicyEngine` evaluates first-class Authentication Policy rules and timestamps.
- `AuthenticationPortalSessionService` enforces idle timer and maximum timer semantics.
- `IdentitySessionSyncService` evolves into a User-ID/authentication-runtime sync service with backward-compatible adapters during migration.

## RADIUS Server Profile Model

`RadiusServerProfile` must become a profile with ordered servers:

- `id`
- `name`
- `description`
- `isActive`
- `administratorUseOnly`
- `authenticationProtocol`
- `timeoutSeconds`
- `retries`
- `certificateProfileId`
- `makeOuterIdentityAnonymous`
- `allowPasswordChangeAfterExpiry`
- `servers`
- `createdAt`
- `updatedAt`
- `createdBy`

`authenticationProtocol` values:

- `pap`
- `chap`
- `peap_mschapv2`
- `peap_gtc`
- `eap_ttls_pap`

Default for new profiles is `peap_mschapv2`, matching PAN-OS current behavior. Existing migrated RaptorGate profiles use `pap` so current deployments do not silently change auth behavior.

Each server item:

- `id`
- `name`
- `host`
- `port`
- `sharedSecretRef`
- `priority`

Validation:

- At least one server is required for active profiles.
- Server order is deterministic by `priority`, then creation order.
- `timeoutSeconds` range is 1..120.
- `retries` range is 1..5.
- `port` range is 1..65535 and defaults to 1812.
- Secret values are resolved per server.
- EAP protocols require `certificateProfileId`.
- `makeOuterIdentityAnonymous` applies only to PEAP-MSCHAPv2, PEAP-GTC, and EAP-TTLS/PAP.
- CHAP must be explicitly selected and documented as requiring reversibly encrypted passwords on compatible RADIUS backends.

Request construction:

- The NAS-Identifier sent to RADIUS is the Authentication Profile name.
- `NAS-IP-Address` is still configurable through the profile/runtime service route, but it must not replace NAS-Identifier semantics.
- `Calling-Station-Id` is the end-user source IP for portal/user flows and the management source address for administrator flows when available.
- `Called-Station-Id` remains configurable and defaults to the Authentication Portal listener identity for portal flows or the management listener identity for admin flows.

Failover:

- For each authentication attempt, try servers in configured order.
- For each server, send initial request and retry after timeout up to `retries`.
- `Access-Reject` is authoritative for the user and stops failover.
- Timeout/unreachable/invalid response moves to next server.
- If all servers are unavailable, result is `unavailable`.
- If a server returns malformed authenticated response, result is `error` for that server and failover continues unless every server fails.

## RADIUS Protocol Support

The RADIUS client must support:

- PAP Access-Request with `User-Password`.
- CHAP Access-Request with `CHAP-Password` and `CHAP-Challenge`.
- PEAP-MSCHAPv2 over EAP-Message.
- PEAP-GTC over EAP-Message.
- EAP-TTLS/PAP over EAP-Message.
- `Access-Accept`, `Access-Reject`, and `Access-Challenge`.
- `State` attribute round-trip during challenge flows.
- `Message-Authenticator` validation and generation where required by EAP/RADIUS behavior.
- Response authenticator validation for every response.
- `Proxy-State` preservation if a server returns it during challenge flows.
- Fragmented `EAP-Message` attributes.

TLS inside PEAP/EAP-TTLS must validate the RADIUS server certificate through the configured certificate profile. If certificate validation fails, authentication fails closed.

Outer identity behavior:

- When `makeOuterIdentityAnonymous` is enabled, outer EAP identity is anonymous while inner identity remains the authenticating username.
- When disabled, outer identity uses the username.

The client should prefer a proven EAP/RADIUS library if one is available and maintainable in the Node/NestJS runtime. If no suitable library exists, protocol code must be isolated into small, well-tested modules with RFC test vectors and packet-level integration tests. The implementation plan must make this choice explicitly after evaluating libraries.

## RADIUS Attribute Model

The RADIUS parser must return a typed result:

```ts
interface RadiusAccessAccept {
  kind: 'accept';
  attributes: RadiusAttributes;
  paloAlto: PaloAltoRadiusAttributes;
}

interface PaloAltoRadiusAttributes {
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
```

`PaloAlto-Admin-Role` must never be inserted into security policy groups.

`PaloAlto-User-Group` must be exposed separately and used by Authentication Profile Allow List evaluation.

Generic attributes such as `Filter-Id`, `Class`, and Cisco AVPair can be retained for diagnostics and optional non-Palo-Alto compatibility, but they must not drive Palo Alto-mode security policy group membership.

## Authentication Profile Model

Authentication Profile becomes the central authorization gate for login:

- `id`
- `name`
- `description`
- `isActive`
- `type`
- `serverProfileId`
- `retrieveUserGroupFromRadius`
- `allowList`
- `failedAttempts`
- `lockoutSeconds`
- `usernameModifier`
- `loginAttribute`
- `adminRoleFallbackMappings`
- `createdAt`
- `updatedAt`
- `createdBy`

`type` values:

- `radius`
- `ldap`
- `local`

`allowList` entries:

- `kind: 'all'`
- `kind: 'user', value: string`
- `kind: 'group', value: string`

Semantics:

- Empty Allow List means no non-local user can authenticate through that profile.
- `all` allows any user accepted by the provider.
- `user` matches normalized username.
- `group` matches provider-specific group data available to the profile.
- For RADIUS, group entries match `PaloAlto-User-Group` only when `retrieveUserGroupFromRadius` is enabled.
- For LDAP, group entries match LDAP group mapping.
- A RADIUS Access-Accept with no matching Allow List entry returns an authorization reject, not provider unavailable.

Lockout:

- Failed attempts are tracked per authentication profile and normalized username.
- Reaching `failedAttempts` locks that username for `lockoutSeconds`.
- Lockout applies before sending a new provider request.
- Successful authentication clears failed-attempt state.
- Authorization denials caused by Allow List do count as failed attempts.
- Provider unavailability does not count as a credential failure.

## Administrator Authorization

External administrator login through RADIUS must use typed Palo Alto VSAs:

- `PaloAlto-Admin-Role` maps to a default dynamic role or custom local admin role profile.
- `PaloAlto-Admin-Access-Domain` maps to a local access domain model.

Role names must be matched case-sensitively for custom roles and lower-case for predefined dynamic roles. RaptorGate role names must be normalized to a Palo Alto-compatible vocabulary:

- `superuser`
- `superreader`
- `deviceadmin`
- `devicereader`
- custom role names

Existing RaptorGate roles (`super_admin`, `admin`, `operator`, `viewer`) need a compatibility mapping layer:

- `super_admin` maps to `superuser`.
- `viewer` maps to `superreader`.
- `admin` and `operator` must become custom admin role profiles, not overloaded dynamic roles.

If RADIUS accepts credentials but sends no usable admin role, the admin login is denied unless an explicit local fallback mapping exists on the Authentication Profile. Fallback mappings are compatibility behavior and must be clearly labeled in config/UI as local overrides, not Palo Alto VSA behavior.

Access domains:

- A new `AdminAccessDomain` config entity maps a name to allowed management scopes.
- Until full virtual systems exist, access domain can restrict visible/allowed zones, interfaces, config sections, and read/write capabilities.
- If a profile requires access domain and RADIUS does not return one, authorization is denied.

Local break-glass admin remains supported and evaluated before external providers, but it must be visibly separate from external RADIUS authorization.

## End-User Authentication and User-ID Mapping

Successful end-user authentication creates or updates a User-ID runtime mapping:

- client IP
- username
- normalized domain/user identity
- provider
- authentication profile id
- authenticated timestamp
- first-factor timestamp
- additional-factor timestamps
- idle expiration
- absolute expiration
- groups from group mapping

The firewall must not treat RADIUS `PaloAlto-User-Group` as `identity_group`. Security policy group membership comes from User-ID group mapping:

- LDAP group mapping is the first supported source.
- Future sources can include Cloud Identity Engine-like connectors.
- RADIUS group VSA is only for Allow List evaluation in Authentication Profile.

Existing `IdentitySession` can evolve into `UserIdMapping` with compatibility field names during migration. Policy matchers should keep user-visible names `identity_user` and `identity_group`, but their source semantics change to User-ID mapping.

## Authentication Policy

Authentication Policy must become a first-class rulebase separate from Security Policy.

An Authentication Policy rule contains:

- `id`
- `name`
- `description`
- `isActive`
- `sourceZones`
- `sourceAddresses`
- `sourceUsers`
- `destinationZones`
- `destinationAddresses`
- `applications`
- `services`
- `urlCategories`
- `authenticationEnforcementObjectId`
- `timeoutSeconds`
- `logSetting`
- `tags`
- `createdAt`
- `updatedAt`
- `createdBy`

Authentication enforcement object:

- `id`
- `name`
- `authenticationProfileId`
- `factorSequence`
- `authMethod`
- `portalMode`
- `mfaVendorProfiles`

Initial implementation must support password-based Authentication Portal as first factor. MFA support must be modeled in the schema and flow so RADIUS MFA/challenge-response and future MFA vendors can fit without redesign.

Packet path behavior:

1. Firewall evaluates Authentication Policy before final Security Policy allow.
2. If traffic does not match Authentication Policy, normal Security Policy evaluation continues.
3. If traffic matches and no valid authentication timestamp exists for the required factors, firewall returns a redirect/block decision toward Authentication Portal.
4. After successful authentication, backend records timestamps and syncs User-ID mapping/timestamp state.
5. Firewall re-evaluates subsequent packets with authenticated User-ID context.
6. Security Policy then decides final allow/drop using source user and group mapping.

Authentication timestamps:

- Stored per client IP, username, authentication rule id, and factor vendor/profile.
- A timestamp for one rule can satisfy another rule only when required authentication factors match.
- Rule timeout and portal maximum timer both apply; whichever expires first causes re-authentication.

## Authentication Portal

Authentication Portal settings:

- `enabled`
- `listenerInterface`
- `listenerZone`
- `bindAddress`
- `bindPort`
- `sslTlsServiceProfileId`
- `defaultAuthenticationProfileId`
- `idleTimerMinutes`
- `maxTimerMinutes`
- `redirectHost`

Timer semantics:

- `idleTimerMinutes` resets on activity by the authenticated portal user.
- `maxTimerMinutes` is absolute and does not reset.
- `maxTimerMinutes` must be greater than or equal to `idleTimerMinutes`.
- Expired idle timer or max timer removes the User-ID mapping and requires re-authentication.

Portal request handling:

- Portal login uses the Authentication Enforcement object selected by the matching Authentication Policy rule when present.
- Default portal authentication profile is used only for default enforcement objects or direct portal login without a policy context.
- Source IP is taken from the trusted proxy/connection path, never from request body.
- Portal session state is backend runtime state and syncs to firewall.

## Runtime Sync Contract

The gRPC identity sync contract must evolve from `IdentityManagerUserSession` to a User-ID/authentication runtime contract.

New payload fields:

- `mapping_id`
- `username`
- `normalized_user`
- `domain`
- `ip_address`
- `provider`
- `authentication_profile_id`
- `source_type`
- `authenticated_at`
- `first_factor_at`
- `factor_timestamps`
- `idle_expires_at`
- `absolute_expires_at`
- `groups`
- `group_source`
- `authentication_policy_rule_id`

Firewall runtime store:

- Keyed by source IP for packet lookup.
- Stores user and groups from User-ID group mapping.
- Stores authentication timestamps separately enough to evaluate Authentication Policy timeouts.
- Treats expired idle or absolute timers as unauthenticated.
- Revoke by IP remains supported.

Replay after firewall restart remains backend-owned. Backend replays live mappings and timestamps to the firewall after reconnect.

## Policy Semantics

Security Policy uses:

- `identity_user` from User-ID username.
- `identity_group` from User-ID group mapping.
- `auth_state` from valid User-ID mapping and timestamp status.

Authentication Policy uses packet/application/url/source/destination criteria and authentication timestamps. It does not directly allow application traffic; it only decides whether authentication is required before Security Policy can allow traffic.

Seeded current rules that simulate pre-auth gating must be replaced by first-class Authentication Policy seed data.

## Configuration, Import, Export, and Rollback

Identity config snapshot must include:

- RADIUS server profiles with ordered servers and protocol options.
- Certificate profiles referenced by RADIUS EAP methods.
- Authentication profiles with Allow List and lockout settings.
- Admin role profiles and access domains.
- Authentication Portal settings.
- Authentication enforcement objects.
- Authentication Policy rules.
- User-ID group mapping settings.

Import/export/apply/rollback must validate references atomically:

- Authentication Profile references existing server profile.
- RADIUS EAP profile references existing certificate profile.
- Authentication enforcement object references existing Authentication Profile.
- Authentication Policy references existing enforcement object.
- Admin role VSA values reference existing dynamic/custom role or are rejected at auth time with clear diagnostics.
- Admin access domain VSA values reference existing access domain or are rejected at auth time.

Runtime User-ID mappings and authentication timestamps are not config snapshot data.

## Migration

Existing config migrates as follows:

- Existing single-server RADIUS profile becomes a profile with one ordered server.
- Existing `timeoutMs` converts to `timeoutSeconds`, rounding up to at least 1.
- Existing `retries` of 0 becomes 1 because PAN-OS server profile retry range starts at 1.
- Existing profiles get `authenticationProtocol: pap` to preserve deployed behavior.
- Existing auth profiles with `groupSource: radius_vsa` become RADIUS profiles with `retrieveUserGroupFromRadius: true` and generated Allow List entries only when the previous behavior clearly intended login authorization by group.
- Existing security policy rules using `identity_group` remain syntactically valid, but their groups now come from LDAP/User-ID group mapping. Migration must warn if those group names were only known from RADIUS VSA.
- Existing admin role mappings move to `adminRoleFallbackMappings`.
- Existing portal session TTL becomes both `idleTimerMinutes` and `maxTimerMinutes` only if no better data exists; migration warning must ask administrator to set distinct values.

Migration must emit warnings in import/apply diagnostics and in backend startup logs. It must not silently preserve incorrect Palo Alto semantics.

## Diagnostics and Audit

Required audit events:

- `auth.radius.request.started`
- `auth.radius.server.timeout`
- `auth.radius.server.unavailable`
- `auth.radius.response.reject`
- `auth.radius.response.accept`
- `auth.radius.response.challenge`
- `auth.radius.response.invalid_authenticator`
- `auth.radius.eap.tls_validation_failed`
- `auth.profile.allow_list.allowed`
- `auth.profile.allow_list.denied`
- `auth.profile.lockout.started`
- `auth.profile.lockout.denied`
- `auth.admin.vsa.authorized`
- `auth.admin.vsa.denied`
- `auth.user_id.mapping.upserted`
- `auth.user_id.mapping.revoked`
- `auth.policy.matched`
- `auth.policy.challenge_required`
- `auth.policy.timestamp.accepted`
- `auth.portal.session.idle_expired`
- `auth.portal.session.absolute_expired`

Diagnostics UI/API must show:

- Per-server RADIUS test result.
- Protocol used.
- Accept/reject/unavailable/error.
- Retrieved Palo Alto VSAs by typed field.
- Allow List decision.
- Admin role/access domain decision.
- User-ID mapping created or not created.

Logs must not include plaintext passwords, shared secrets, EAP keys, or full token values.

## Error Handling

Credential reject:

- `Access-Reject` or provider credential failure.
- Counts toward lockout.
- Does not fail over to the next RADIUS server.

Authorization reject:

- Provider accepted credentials but Authentication Profile Allow List or admin VSA authorization denied access.
- Counts toward lockout for end-user Authentication Profile.
- Does not create User-ID mapping.

Provider unavailable:

- Timeout or network failure across all eligible servers.
- Does not count toward lockout.
- Produces unavailable diagnostics.

Provider protocol error:

- Invalid authenticator, malformed packet, EAP TLS validation failure, unsupported challenge.
- Fails closed.
- Does not create User-ID mapping.

Configuration error:

- Missing referenced profile, EAP without certificate profile, invalid access domain, inactive profile.
- Fails closed before sending provider request when detectable.

## Testing Strategy

Unit tests:

- RADIUS packet encoding and decoding for PAP, CHAP, and EAP attributes.
- Response authenticator verification rejects tampered packets.
- Message-Authenticator generation and verification.
- Access-Challenge state preservation.
- EAP-Message fragmentation and reassembly.
- Palo Alto VSA parser separates Admin Role, Admin Access Domain, Panorama fields, User Group, and endpoint fields.
- `PaloAlto-Admin-Role` never appears in policy groups.
- RADIUS server failover stops on `Access-Reject` and continues on timeout.
- RADIUS server failover honors preferred order.
- Authentication Profile Allow List denies empty list.
- Authentication Profile Allow List allows explicit user.
- Authentication Profile Allow List allows RADIUS `PaloAlto-User-Group` only when retrieval is enabled.
- Lockout starts after configured failed attempts.
- Provider unavailable does not increment failed attempts.
- Admin authorization accepts valid VSA role and access domain.
- Admin authorization denies missing/unknown role.
- Authentication Portal idle timer resets on activity.
- Authentication Portal max timer does not reset.
- Authentication Policy timestamp satisfies only compatible factor sets.
- Security Policy `identity_group` uses LDAP/User-ID groups, not RADIUS VSA groups.

Integration tests:

- FreeRADIUS PAP end-user login with Allow List user match.
- FreeRADIUS PAP end-user login with `PaloAlto-User-Group` Allow List match.
- FreeRADIUS PAP admin login with `PaloAlto-Admin-Role`.
- FreeRADIUS Access-Reject stops server failover.
- Multi-server timeout failover reaches second server.
- PEAP-MSCHAPv2 login validates server certificate.
- PEAP-GTC login handles Access-Challenge.
- EAP-TTLS/PAP login validates inner PAP result.
- Authentication Policy match redirects unauthenticated flow.
- Successful portal login creates User-ID mapping and Security Policy sees user/group.
- Idle expiry removes mapping.
- Absolute expiry removes mapping even with activity.
- Firewall restart replay restores live mappings and timestamps.

Manual/interop tests:

- Microsoft NPS PAP or PEAP-MSCHAPv2 with RaptorGate as RADIUS client.
- FreeRADIUS dictionary with Palo Alto vendor 25461.
- Wrong shared secret rejects response authenticator.
- Expired/unknown RADIUS server certificate fails EAP.
- Admin custom role and access domain returned by VSA.

## Implementation Decomposition

This is a large change and must be implemented as a sequence of production-quality slices:

1. Typed RADIUS attributes and Palo Alto VSA split, while preserving current PAP behavior.
2. RADIUS server profile ordered server model and failover.
3. Authentication Profile Allow List, lockout, and RADIUS group retrieval semantics.
4. Admin role/access domain VSA authorization.
5. User-ID mapping semantics and removal of RADIUS VSA as policy group source.
6. First-class Authentication Policy and enforcement object model.
7. Authentication Portal idle/max timer and timestamp sync.
8. CHAP support.
9. PEAP-MSCHAPv2, PEAP-GTC, and EAP-TTLS/PAP support with certificate profiles.
10. UI/API diagnostics and import/export/rollback completion.

Each slice must include backend tests, firewall tests where packet-path behavior changes, config import/export tests when schemas change, and a migration test if existing persisted JSON/proto state changes.

## Acceptance Criteria

RaptorGate is considered aligned with Palo Alto-style RADIUS behavior when:

- New RADIUS server profiles support ordered servers, timeout, retries, protocol choice, EAP certificate profile, and anonymous outer identity.
- RADIUS server failover behavior matches PAN-OS: reject stops, timeout/unavailable continues.
- PAP, CHAP, PEAP-MSCHAPv2, PEAP-GTC, and EAP-TTLS/PAP work against a real RADIUS server.
- `PaloAlto-Admin-Role`, `PaloAlto-Admin-Access-Domain`, and `PaloAlto-User-Group` are parsed and consumed by their correct subsystems.
- Authentication Profile Allow List gates successful provider authentication.
- RADIUS user group VSA is used for Allow List matching and not for Security Policy groups.
- Admin authorization can be controlled by RADIUS VSA role and access domain.
- Authentication Policy controls when users must authenticate before Security Policy allows protected traffic.
- Authentication Portal enforces idle and maximum timers.
- User-ID mappings and authentication timestamps survive firewall restart through backend replay.
- Import/export/apply/rollback preserve the full identity configuration and reject invalid references.
- Diagnostics clearly explain provider result, profile authorization result, admin authorization result, and User-ID mapping result.
