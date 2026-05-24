# Identity RADIUS LDAP Enforcement Tests Plan

Goal: add test-env coverage and a manual frontend checklist for identity enforcement with RADIUS and LDAP.

## Scope

- Automated test-env coverage verifies:
  - RADIUS portal authentication with LDAP group resolution.
  - LDAP portal authentication with LDAP group resolution.
  - pre-auth h1 -> h2 traffic is blocked.
  - wrong credentials do not create a session.
  - `user` in group `users` is allowed to h2 port 8080.
  - `guest` in group `guests` authenticates but remains blocked by policy.
  - logout removes enforcement and blocks traffic again.
- Manual documentation verifies the same flow through frontend Identity, Policy Engine, Config, Portal, and Active Sessions views.

## Implementation

- [x] Add `test-env/src/tests/identity-enforcement-helpers.ts`
  - Uses backend HTTPS API on r1 for profile setup.
  - Uses managed secrets for RADIUS and LDAP profile refs.
  - Pushes an identity-aware RaptorLang snapshot through `PushActiveConfigSnapshot`.
  - Provides portal login/logout/session checks and h1 -> h2 allow/block assertions.
- [x] Add `test-env/src/tests/identity-enforcement.test.ts`
  - Keeps RADIUS and LDAP scenarios in one file so profile and policy changes execute sequentially.
  - Restarts and verifies the existing h2 `h2-http` service before traffic checks.
- [x] Add `docs/identity-radius-ldap-enforcement-manual-tests.md`
  - Lists exact frontend fields and expected results.
  - Includes the policy content and snapshot apply step needed for enforcement.

## Verification

Do not run the full Bun suite here. The intended verification command is the existing test-env `run.sh`, executed manually by the project owner.

Light checks performed during implementation:

- `git diff --check`
- static inspection of changed test and doc files
