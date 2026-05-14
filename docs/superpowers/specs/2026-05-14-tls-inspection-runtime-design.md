# TLS Inspection Runtime Design

## Goal

Make RaptorGate TLS inspection behave like a real NGFW runtime: session metadata drives plaintext inspection, upstream connections use enforced firewall routing decisions, nft redirect state follows configuration snapshots, and TLS security decisions are explicit policy decisions.

## Baseline

Issue 1 is already implemented in commits `9d742fb259cbe2d55547455461889d0bf3059cb7` and `16cbb0212817cbaa839a6144b20bc87cdb3ac002`.

The current baseline already includes explicit TLS `SessionMeta` with session id, peer/server/original destination, SNI, ALPN, inspection mode, and client/server-side interfaces. `DecryptedChainInspector` already uses `SessionMeta::source_interface_for_direction()` so C2S plaintext uses the client-side interface and S2C plaintext uses the server-side interface.

This design treats that work as the baseline. The new work must not rewrite `SessionMeta` or plaintext direction handling unless a specific regression test shows it is necessary.

## Non-Goals

This design does not add QUIC or HTTP/3 inspection.

This design does not decrypt traffic from captured ciphertext alone.

This design does not add a full Palo Alto-style UI or full decryption profile management UI.

This design does not add a permissive production mode for unenforced upstream egress.

## Runtime Principles

Production TLS MITM has no "best effort" egress path. If RaptorGate cannot prove and enforce the upstream egress interface selected by firewall routing, the session fails closed.

The runtime responsibilities are split as follows:

- `SessionMeta` carries session context for decrypted inspection.
- `UpstreamConnector` owns upstream TCP connection creation and egress enforcement.
- `TlsRedirectManager` owns transparent TLS redirect lifecycle.
- `TlsDecisionEngine` owns TLS security decisions.
- `MitmProxy` executes decisions and relays traffic. It does not choose egress interfaces or certificate failure policy itself.

## Upstream Egress Enforcement

`MitmProxy` must not call `tokio::net::TcpStream::connect()` directly for upstream traffic. All upstream TCP connections must go through an `UpstreamConnector`.

This includes:

- outbound MITM upstream connections to the original destination,
- inbound inspection re-encryption connections to the internal server,
- TCP passthrough connections used after TLS bypass or non-TLS detection.

The production connector is `LinuxUpstreamConnector`. It performs this sequence for every upstream connection:

1. Run `RoutingTable::route_lookup(dst.ip())`.
2. Resolve the returned `SystemInterfaceId` through `InterfaceMonitor::get_by_index()`.
3. Validate the interface record and interface name.
4. Create a socket manually.
5. Apply `SO_BINDTODEVICE` to the socket before `connect()`.
6. Connect the bound socket to the destination.
7. Convert the connected socket into `tokio::net::TcpStream`.

The connector fails closed for each of these cases:

- no route for destination IP,
- no interface record for the resolved interface id,
- empty or invalid interface name,
- socket creation failure,
- `SO_BINDTODEVICE` failure,
- TCP connect failure.

`SO_BINDTODEVICE` is Linux-specific. Strict TLS upstream egress enforcement requires Linux and root, `CAP_NET_RAW`, or equivalent privileges sufficient to bind a socket to an interface.

When TLS MITM is enabled, startup must run a privilege preflight. If the process does not have required Linux privileges, production TLS MITM startup fails instead of silently running with unenforced egress. Runtime still treats every per-session bind/connect failure as fail closed because capabilities, interfaces, and routes can change after startup.

Unit tests must not require real `SO_BINDTODEVICE`. Production connector logic should be split into testable parts such as egress interface resolution, socket binding operations, and bound connect operations. Unit tests use fake socket operations or `FakeUpstreamConnector` under `#[cfg(test)]`. Real `SO_BINDTODEVICE` behavior belongs in a manual or privileged integration smoke test.

The runtime must emit structured logs or events for upstream connection lifecycle:

- `tls.upstream.connect.started` with session id, destination, resolved interface, inspection mode, SNI, and original destination.
- `tls.upstream.connect.bound` after the socket is bound to the interface.
- `tls.upstream.connect.failed` with reason, destination, resolved interface when known, OS error when known, inspection mode, SNI, and session id.

## Transparent Redirect Lifecycle

Transparent TLS redirect is runtime state, not a one-time startup side effect. If a configuration snapshot changes sniffed interfaces, the sniffer and nft redirect state must be reconciled together.

`TlsRedirectManager` owns TLS transparent redirect lifecycle. It receives desired redirect state from startup config and accepted configuration snapshots:

- TLS inspection enabled or disabled,
- MITM listen address,
- redirected ports,
- sniffed OS interface names,
- local firewall addresses excluded from redirect.

The manager keeps desired state separate from applied state. It also tracks a generation counter and the last apply result for logging and debugging.

`TlsRedirectManager::reconcile()` semantics:

- Disabled: uninstall existing redirect if present, then no-op.
- Enabled with empty sniffed interfaces: uninstall existing redirect and return a configuration error so the snapshot is rejected.
- Enabled with unchanged desired state: no-op.
- Enabled with changed desired state: replace the nft redirect table with rules rendered from the desired state.

Redirect replacement must be idempotent. Calling `reconcile()` multiple times with the same desired state must not duplicate rules or fail because a rule already exists. The final nft state must match the desired state.

Replacement must use a full rendered ruleset instead of incremental ad hoc rule edits. The rendered operation should delete the old RaptorGate TLS table if present, create the table and chain, and add the complete current rule set for current interfaces, ports, listen address, and local-address bypasses.

Snapshot apply must call redirect reconcile after `zone_interface_store.swap_zone_interfaces()` and after the new sniffed OS interface names are computed. This is the point where the sniffer already has the same logical target state the redirect manager must enforce.

The runtime must emit structured logs or events:

- `tls.redirect.reconcile.started` with generation, old interfaces, new interfaces, ports, and listen address.
- `tls.redirect.reconcile.installed` with generation, interfaces, ports, and listen address.
- `tls.redirect.reconcile.uninstalled` with generation and reason.
- `tls.redirect.reconcile.failed` with generation, reason, command exit code when known, and OS error when known.

## TLS Security Decisions

`TlsDecisionEngine` owns TLS security decisions. `RecordingVerifier` only records whether the upstream certificate was trusted. `MitmProxy` executes the decision returned by `TlsDecisionEngine`.

The TLS policy model includes:

- bypass domains,
- known pinned domains,
- ECH policy,
- untrusted upstream certificate action.

The untrusted upstream certificate action has these values:

- `Block`
- `ForwardWithUntrustCa`

Pre-handshake decision remains responsible for:

- inbound server-key inspection eligibility,
- inbound bypass when the server key entry is disabled or configured to bypass,
- bypass domain matches,
- known pinned domain matches,
- automatic pinning bypass,
- ECH block/no-block behavior,
- intercept eligibility.

After the upstream TLS handshake, `MitmProxy` calls a post-handshake decision method on `TlsDecisionEngine`. The decision type is explicit:

```rust
pub enum PostHandshakeTlsDecision {
    ContinueWithNormalForgery,
    ContinueWithUntrustForgery,
    Block { reason: TlsBlockReason },
}
```

Post-handshake decision semantics:

- Trusted upstream certificate: `ContinueWithNormalForgery`.
- Untrusted upstream certificate and policy `Block`: fail closed before `accept_client_tls`.
- Untrusted upstream certificate and policy `ForwardWithUntrustCa`: continue with a certificate forged by the Untrust CA.

The block decision must happen before accepting client TLS. The client must not receive an accepted MITM TLS session and forged certificate before RaptorGate decides that the upstream certificate failure should block the flow.

Bypass flows do not run post-handshake MITM certificate policy because they do not enter outbound MITM certificate forgery.

The runtime must emit a common decision event and specific untrusted-certificate events:

- `tls.decision.post_handshake` with session id, SNI, destination, upstream trust result, decision, and reason.
- `tls.upstream.cert.untrusted.detected`.
- `tls.upstream.cert.untrusted.blocked`.
- `tls.upstream.cert.untrusted.forward_untrust_ca`.

## Data Flow

Outbound MITM flow:

1. Transparent redirect sends client TCP flow to `MitmProxy`.
2. `MitmProxy` reads original destination and peeks ClientHello.
3. `TlsDecisionEngine` returns the pre-handshake decision.
4. Bypass or block decisions exit the MITM path.
5. Intercept decisions call `UpstreamConnector` to connect to the original destination with enforced egress.
6. Upstream TLS handshake runs before accepting client TLS.
7. `RecordingVerifier` records upstream trust state.
8. `TlsDecisionEngine` returns the post-handshake decision.
9. Block decisions fail closed before accepting client TLS.
10. Continue decisions forge the normal or Untrust CA certificate and accept client TLS.
11. `InspectionRelay` relays both directions with `SessionMeta`.
12. `DecryptedChainInspector` builds synthetic packet contexts from `SessionMeta` direction interfaces.

Inbound inspection flow:

1. Transparent redirect sends inbound client TCP flow to `MitmProxy`.
2. `MitmProxy` reads original destination and checks `ServerKeyStore`.
3. `TlsDecisionEngine` returns the pre-handshake decision.
4. Bypass or block decisions exit the inbound inspection path.
5. Intercept decisions call `UpstreamConnector` to connect to the internal server with enforced egress.
6. RaptorGate connects upstream with no-verify re-encryption using the selected ALPN.
7. RaptorGate accepts client TLS with the configured inbound server certificate.
8. `InspectionRelay` relays both directions with `SessionMeta`.

Passthrough flow:

1. Non-TLS traffic on an inspected port or TLS bypass uses TCP passthrough.
2. Passthrough still calls `UpstreamConnector` for the upstream TCP connection.
3. Passthrough does not accept client TLS, forge certificates, or run decrypted classification.

## Testing Strategy

Issue 1 and the existing C2S/S2C plaintext direction behavior remain baseline coverage. New tests add regression protection where new runtime changes could break that behavior.

Required unit tests:

- `LinuxUpstreamConnector` resolves destination route to interface id and interface name.
- `LinuxUpstreamConnector` fails closed on missing route.
- `LinuxUpstreamConnector` fails closed on missing interface record.
- `LinuxUpstreamConnector` fails closed on empty interface name.
- `LinuxUpstreamConnector` fails closed on bind failure.
- `LinuxUpstreamConnector` applies bind before connect through fake socket operations.
- `MitmProxy` uses `UpstreamConnector` for outbound MITM upstream.
- `MitmProxy` uses `UpstreamConnector` for inbound re-encryption upstream.
- `MitmProxy` uses `UpstreamConnector` for TCP passthrough.
- `TlsRedirectManager` renders enabled rules for multiple interfaces and ports.
- `TlsRedirectManager` reconcile unchanged state is no-op.
- `TlsRedirectManager` reconcile changed state replaces the redirect table.
- `TlsRedirectManager` reconcile disabled state uninstalls or no-ops.
- `TlsRedirectManager` reconcile enabled empty interfaces uninstalls and returns config error.
- Snapshot apply calls redirect reconcile after zone interface swap and sniffed interface name resolution.
- `TlsDecisionEngine` returns normal forgery for trusted upstream cert even when untrusted policy is `Block`.
- `TlsDecisionEngine` returns block for untrusted upstream cert and policy `Block`.
- `TlsDecisionEngine` returns Untrust CA forgery for untrusted upstream cert and policy `ForwardWithUntrustCa`.
- Bypass domains do not enter post-handshake MITM decision.
- Existing ECH, pinned, bypass, and inbound server-key decisions do not regress.

Manual or privileged integration smoke tests:

- Outbound HTTPS MITM logs `tls.redirect.reconcile.installed`, `tls.upstream.connect.started`, `tls.upstream.connect.bound`, `tls.decision.post_handshake`, client TLS acceptance, and decrypted classification.
- Bypass domain shows no forged certificate, no `accept_client_tls` MITM path, no decrypted classification, and upstream passthrough uses `UpstreamConnector` when the proxy creates the upstream connection.
- Changing sniffed interface configuration replaces nft rules so the rendered script contains only the new interfaces.
- Running TLS MITM without required privileges fails startup preflight or fails closed on the first bind attempt, with a clear log reason.

## Documentation

Add `docs/tls-inspection-runtime.md` with:

- TLS inspection runtime flow,
- required Linux privileges for strict egress enforcement,
- fail-closed cases,
- transparent redirect reconcile behavior,
- untrusted upstream certificate policy,
- debug log/event names and what they mean,
- known limits.

Known limits must include:

- QUIC and HTTP/3 are not inspected by this TLS MITM path.
- ECH can prevent useful SNI-based policy unless blocked or mitigated by DNS policy.
- mTLS and certificate pinning can cause client-side handshake failures; known pinned and automatic pinning bypass behavior remain policy-driven.
- RaptorGate does not decrypt historical ciphertext without session keys.
- Strict upstream egress enforcement is Linux-specific because it relies on `SO_BINDTODEVICE`.

## Acceptance Criteria

The implementation is complete when:

- No direct upstream `TcpStream::connect()` remains in `MitmProxy` outside connector internals.
- Production upstream connector enforces `SO_BINDTODEVICE` before `connect()`.
- TLS MITM startup checks privileges when inspection is enabled.
- All upstream egress failures fail closed.
- Redirect nft state is reconciled on startup and after accepted interface snapshot changes.
- TLS inspection rejects enabled snapshots with no sniffed interfaces after uninstalling stale redirect state.
- Untrusted upstream certificate handling is controlled by `TlsDecisionEngine`.
- Untrusted certificate block happens before `accept_client_tls`.
- Unit tests cover connector, redirect manager, post-handshake decisions, and snapshot reconcile behavior.
- Manual smoke tests demonstrate enforced egress, redirect replacement, MITM classification, and bypass behavior.
- `docs/tls-inspection-runtime.md` explains runtime behavior and limits.
