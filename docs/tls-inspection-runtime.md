# TLS Inspection Runtime

RaptorGate TLS inspection is strict runtime state, not best effort packet logging. The runtime path is:

1. nft transparent redirect sends configured TLS ports from sniffed interfaces to the MITM listener.
2. `MitmProxy` reads the original destination and peeks ClientHello.
3. `TlsDecisionEngine` makes the pre-handshake decision: bypass, block, inbound inspection, or outbound inspection.
4. `UpstreamConnector` resolves firewall egress, binds the socket to the resolved interface, then connects upstream.
5. Upstream TLS handshake runs before client TLS is accepted.
6. `RecordingVerifier` records upstream certificate trust.
7. `TlsDecisionEngine` makes the post-handshake certificate decision.
8. `MitmProxy` executes the decision and `InspectionRelay` forwards decrypted plaintext to DPI.

## Required Privileges

Strict upstream egress enforcement is Linux-specific and uses `SO_BINDTODEVICE`.

TLS MITM requires root, `CAP_NET_RAW`, or equivalent privileges. Startup runs a bind preflight when TLS inspection is enabled. Runtime still fails closed on every route, interface, bind, or connect failure because capabilities, interfaces, and routes can change after startup.

## Fail Closed Cases

TLS upstream connection fails closed when:

- route lookup has no route for the upstream destination,
- the resolved interface has no monitor record,
- the resolved interface has no usable name,
- binding the socket to the interface fails,
- the upstream connect fails,
- upstream certificate is untrusted and policy says `Block`.

TLS redirect reconcile fails closed when TLS inspection is enabled with no sniffed interfaces. The manager removes stale redirect state and the snapshot is rejected.

## Redirect Reconcile

`TlsRedirectManager` owns nft redirect state. Startup and snapshot apply call `reconcile()` with desired state:

- disabled: uninstall existing redirect if present,
- enabled with empty sniffed interfaces: uninstall existing redirect and return an error,
- unchanged: no-op,
- changed: replace the full nft table from a rendered ruleset.

The rendered ruleset includes the current listen address, redirected ports, sniffed interface names, and local firewall addresses excluded from redirect. Snapshot apply reconciles redirect after zone interface swap and sniffed interface name resolution.

There is no full transactional rollback for every store touched by snapshot apply. Redirect failure returns `accepted=false` and removes stale redirect state, but already swapped in-memory stores are not globally rolled back.

## Certificate Policy

`RecordingVerifier` only measures whether the upstream certificate was trusted. It does not choose security action.

`TlsDecisionEngine` owns the post-handshake decision:

- trusted upstream certificate: continue with normal forged certificate,
- untrusted upstream certificate and `Block`: close before accepting client TLS,
- untrusted upstream certificate and `ForwardWithUntrustCa`: continue with Untrust CA forged certificate.

The block decision happens before `accept_client_tls`, so the client never gets an accepted forged MITM session for an upstream certificate that policy blocks.

## Debug Events

Useful events:

- `tls.redirect.reconcile.started`
- `tls.redirect.reconcile.installed`
- `tls.redirect.reconcile.uninstalled`
- `tls.redirect.reconcile.noop`
- `tls.redirect.reconcile.failed`
- `tls.upstream.connect.started`
- `tls.upstream.connect.bound`
- `tls.upstream.connect.failed`
- `tls.decision.post_handshake`
- `tls.upstream.cert.untrusted.blocked`
- `tls.upstream.cert.untrusted.forward_untrust_ca`
- `tls.decrypted_traffic.classified`

## Known Limits

- QUIC and HTTP/3 are not decrypted by this TLS MITM path.
- mTLS and certificate pinning can cause client-side handshake failures.
- ECH can limit SNI visibility unless DNS ECH mitigation or policy blocks it first.
- Historical ciphertext cannot be decrypted without session keys.
- `SO_BINDTODEVICE` strict egress enforcement is Linux-specific.
- This is not a full Palo Alto clone and does not implement full PBF or decryption profile UI.
