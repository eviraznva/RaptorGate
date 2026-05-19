# Full L4 TLS-to-HTTP Inspection Design

## Goal

Implement TLS inspection as a first-class L4 session pipeline, not as a transparent redirect proxy and not as a synthetic packet path.

The final production flow is:

```text
real packet
  -> normal packet DataPipeline
  -> Conntrack
  -> SessionManager per-flow task
  -> TCP L4 pipeline
    -> TLS L4 inspection for HTTPS flows
    -> decrypted plaintext chunks
    -> DecryptedFlowPipeline for DPI, IPS, and policy
    -> HttpL4Stage for HTTP parser state
    -> generated encrypted TCP packets back to the real network path
```

Plain HTTP and decrypted HTTPS must use the same HTTP L4 stage after the TLS boundary.

## Current State

This branch already has the earlier packet-free plaintext inspection work:

- `crates/raptorgate/src/tls/decrypted_flow.rs` provides `DecryptedFlowContext`, `DecryptedFlowPipeline`, `DecryptedDpiStage`, `DecryptedIpsStage`, `DecryptedPolicyStage`, and `DecryptedFlowInspector`.
- `crates/raptorgate/src/main.rs` constructs `DecryptedFlowInspector` for the existing MITM runtime.
- TLS plaintext inspection no longer needs to build fake decrypted Ethernet/IP/TCP packets for `DecryptedFlowPipeline`.
- `crates/raptorgate/src/l4/http.rs` starts an HTTP L4 stage that consumes plaintext bytes and stores HTTP DPI state.
- `crates/raptorgate/src/l4/tls.rs` starts a TLS-to-HTTP handoff contract.
- `crates/raptorgate/src/l4/factory.rs` starts selecting HTTP for port 80, SMTP for SMTP ports, and passthrough for other TCP.

That is the current branch gap, not a planned intermediate milestone. Port 443 still does not run through a real TLS L4 decrypt pipeline. The old production TLS path still relies on `TransparentRedirect` and `MitmProxy`.

## Problem

The current production TLS runtime is separate from the L4 session pipeline:

```text
nft redirect
  -> local MitmProxy socket
  -> dual TLS sessions
  -> InspectionRelay
  -> DecryptedFlowInspector
```

That path can inspect TLS, but it is not the architecture needed by the per-flow L4 pipeline. It depends on kernel redirect ownership and a local listener. It does not let an L4 HTTP session stage call TLS inspection and receive plaintext HTTP bytes in the same per-flow L4 task.

The target architecture needs the TLS stage to be part of the same TCP session ownership model as HTTP and SMTP. The TLS stage must consume encrypted TCP stream bytes from `SessionManager`, emit plaintext chunks internally, and emit only legitimate encrypted TCP packets back to the network.

## Non-Goals

This spec does not implement Palo Alto PAN-OS internals.

This spec does not add QUIC or HTTP/3 inspection.

This spec does not add a new TLS policy UI.

This spec does not remove `PacketContext` from the normal packet path.

This spec does not keep transparent redirect as the production TLS inspection path. The old redirect/proxy code may remain in the tree for unit-test compatibility, but final startup wiring must use the L4 TLS path for managed HTTPS inspection.

## Required Architecture

### Normal Packet Path

The normal packet path still receives real packets and builds `PacketContext`:

```text
PacketContext
  -> Validation
  -> Metrics
  -> Ownership
  -> Identity
  -> Conntrack
  -> SessionHandoffStage
  -> later packet stages for packets not owned by L4
```

`SessionHandoffStage` admits payload into `SessionManager`. For L4-owned HTTPS flows, the original encrypted payload packets are consumed by the L4 session and must not also be forwarded as normal packets.

### L4 Session Ownership

`SessionManager` owns a TCP flow once a handle exists for that flow. A TCP L4 stage can decide one of these outcomes for each payload:

- forward the original packet unchanged,
- drop the original packet,
- terminate the session with optional TCP reset,
- emit generated TCP packets carrying bytes produced by an L4 stage.

Generated packets are allowed because they are real network ciphertext or control packets. Decrypted plaintext must never be wrapped in generated packets.

### Managed TCP Endpoint

TLS MITM inside L4 needs a managed TCP endpoint for the client side. The firewall must act as the TCP peer for the original client, not merely observe bytes.

The managed endpoint must track:

- original client/server tuple,
- direction,
- last payload sequence,
- ACK numbers,
- window values needed for generated packets,
- interface metadata for generated egress,
- packet ids that were consumed by L4 and should be dropped from normal release.

The managed endpoint exposes an async byte stream to TLS code:

```rust
pub struct L4TcpEndpoint {
    pub reader: L4TcpReadHalf,
    pub writer: L4TcpWriteHalf,
}
```

`L4TcpReadHalf` receives encrypted payload bytes admitted by `SessionManager`.

`L4TcpWriteHalf` receives encrypted bytes produced by rustls and asks `SessionManager` to emit generated TCP packets in the correct direction.

### TLS L4 Stage

`TlsL4DecryptStage` is the HTTPS stage in the TCP L4 pipeline.

It receives encrypted TCP payload bytes from `SessionManager::on_ct_payload()`. It owns session-local state:

- ClientHello peek buffer,
- SNI,
- ALPN,
- ECH detection result,
- decision from `TlsDecisionEngine`,
- forged certificate selection,
- TLS server session toward the client,
- TLS client session toward the upstream server,
- `InspectionRelay` or equivalent plaintext relay,
- `DecryptedFlowPipeline`,
- `HttpL4Stage`.

The stage must support:

- intercept,
- bypass,
- block,
- inbound server key inspection when configured,
- mirror of approved/dropped plaintext,
- pinning detector behavior through `TlsDecisionEngine`.

### Plaintext Handoff

The TLS stage emits plaintext internally as chunks:

```rust
pub struct L4PlaintextChunk {
    pub direction: Direction,
    pub payload: Vec<u8>,
    pub app_proto: AppProto,
    pub dpi: DpiContext,
}
```

Each chunk is inspected by `DecryptedFlowPipeline`. If allowed and HTTP-compatible, the same bytes are passed to `HttpL4Stage`.

The HTTP stage must be reached for both:

- plain HTTP on port 80,
- decrypted HTTPS on port 443.

### No Synthetic Plaintext Packets

The TLS L4 path must not:

- construct Ethernet/IP/TCP headers for decrypted payload,
- call `PacketContext::from_raw()` for decrypted plaintext,
- call packet `Stage::process()` for decrypted plaintext,
- send decrypted plaintext to `TunForwarder`,
- run conntrack, NAT, redirect ownership, or execution sink on decrypted plaintext.

The generated encrypted output path may call `PacketContext::from_raw()` only for generated ciphertext or TCP control packets that are actually sent on the network.

## Production Wiring

Final startup wiring must use one production TLS inspection path for managed HTTPS:

```text
DaemonV2::assemble_v2
  -> SessionManager::new(...)
  -> TcpL4PipelineFactory::new_application_router(...)
  -> port 443 selects TlsHttpL4Stage
```

`main.rs` must not install `TransparentRedirect` and must not spawn `MitmProxy` for the same managed outbound HTTPS path.

If inbound TLS server-key inspection remains required, it must be represented in the L4 TLS pipeline using the same `TlsL4DecryptStage` family, not by a second production redirect path.

## Required File Boundaries

- `crates/raptorgate/src/l4/stage.rs`: async L4 trait and outcomes that can consume/drop/emit packets.
- `crates/raptorgate/src/l4/http.rs`: HTTP L4 parser state for plaintext HTTP.
- `crates/raptorgate/src/l4/tls.rs`: L4 TLS stage interface and TLS-to-HTTP stage composition.
- `crates/raptorgate/src/l4/tcp_endpoint.rs`: managed TCP byte endpoint and generated packet emission.
- `crates/raptorgate/src/l4/factory.rs`: TCP pipeline selection by application port and protocol.
- `crates/raptorgate/src/conntrack/session_manager.rs`: async per-flow L4 runtime, pending packet consumption, generated packet release.
- `crates/raptorgate/src/tls/dual_session.rs`: generic async IO TLS accept/connect helpers, not hardcoded to `tokio::net::TcpStream`.
- `crates/raptorgate/src/tls/inspection_relay.rs`: reusable plaintext relay for any async IO halves.
- `crates/raptorgate/src/tls/decrypted_flow.rs`: plaintext DPI, IPS, and policy engine reused by L4 TLS.
- `crates/raptorgate/src/main.rs`: remove production redirect/proxy startup for managed HTTPS and wire L4 dependencies.
- `vagrant/deploy.sh` and `vagrant/` topology: test-env smoke runs through h2/r1/h2 routing.

## Acceptance Criteria

Unit and integration criteria:

- `HttpL4Stage` parses direct HTTP plaintext on port 80.
- Port 443 selects a TLS L4 pipeline, not passthrough.
- TLS L4 intercept emits plaintext chunks without building `PacketContext` for plaintext.
- TLS L4 allowed HTTP plaintext reaches `HttpL4Stage`.
- TLS L4 blocked plaintext drops the flow and does not emit encrypted bytes.
- TLS L4 bypass forwards original encrypted packets unchanged.
- `DecryptedFlowPipeline` is reused by TLS L4 before HTTP state handling.
- `SessionManager` can consume original packet ids and emit generated encrypted packets.
- `dual_session` accepts generic async IO for the client side, while the upstream side can still use `TcpStream`.
- No production startup path installs transparent redirect for managed outbound HTTPS.

Test-env criteria:

- `vagrant/deploy.sh` succeeds.
- From `h2`, `openssl s_client -connect www.google.com:443 -servername www.google.com -showcerts` shows a certificate issued by `RaptorGate CA`.
- From `h2`, an HTTPS GET to `www.google.com` returns HTTP content.
- Client output contains no mixed `RGDM` or decrypted mirror bytes.
- r1 logs show the L4 TLS pipeline path, not nft redirect ownership.
- Turning on an IPS signature that matches decrypted HTTP blocks the HTTPS flow.
- Turning on bypass policy for a domain forwards the original TLS connection without forged RaptorGate certificate.

## Completion Definition

This work is complete only when port 443 HTTPS traffic in the vagrant topology is handled by the L4 session pipeline and not by transparent redirect. A design that only keeps `DecryptedFlowContext` behind `MitmProxy` is not complete.
