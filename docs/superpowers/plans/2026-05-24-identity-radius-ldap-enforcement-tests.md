# Identity RADIUS LDAP Enforcement Tests Plan

Goal: add test-env coverage and a manual frontend checklist for identity enforcement with RADIUS and LDAP.

## Scope

- Automated test-env coverage verifies:
  - RADIUS provider accept/reject against the lab FreeRADIUS service.
  - LDAP provider accept/reject and group lookup against the lab LDAP service.
  - pre-auth h1 -> h2 traffic is blocked.
  - `user` in group `users` is inserted into firewall runtime identity sessions and allowed to h2 port 8080.
  - `guest` in group `guests` is inserted into firewall runtime identity sessions and remains blocked by policy.
  - session revoke removes enforcement and blocks traffic again.
- Manual documentation verifies the same flow through frontend Identity, Policy Engine, Config, Portal, and Active Sessions views.

## Implementation

- [x] Add `test-env/src/tests/identity-enforcement-helpers.ts`
  - Stays compatible with `test-env/run.sh`, which deploys r1 with `--no-backend`.
  - Uses real `radtest`, `ldapwhoami`, and `ldapsearch` checks from r1.
  - Syncs runtime identity sessions directly to the firewall through `IdentitySessionService` on the forwarded query socket.
  - Pushes an identity-aware RaptorLang snapshot through `PushActiveConfigSnapshot`.
  - Provides h1 -> h2 allow/block assertions.
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
