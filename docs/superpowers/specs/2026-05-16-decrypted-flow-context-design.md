# Decrypted Flow Context Design

## Goal

Replace TLS plaintext inspection through synthetic Ethernet/IP/TCP packets with a first-class decrypted flow model, and make that model compatible with a later L4 TLS-to-HTTP handoff.

After this change, decrypted TLS payloads are inspected as plaintext flow chunks with explicit session metadata. They must not be converted into fake raw packets and must not pass through the normal packet forwarding pipeline.

The long-term target is that a TCP L4 TLS stage accepts encrypted TLS bytes, maintains TLS session state, emits plaintext application bytes, and passes HTTP plaintext to an HTTP L4 stage. This spec first removes the synthetic packet bridge, then defines the L4 handoff contract that future work must preserve.

## Problem

RaptorGate currently decrypts TLS in `MitmProxy` and `InspectionRelay`, then calls `DecryptedChainInspector`. `DecryptedChainInspector` builds a synthetic Ethernet/IP/TCP packet from plaintext bytes and passes that `PacketContext` through the main `DataPipeline`.

That design is unsafe and misleading:

- plaintext is not a packet received from an interface,
- fake Ethernet addresses and TCP sequence values are invented,
- the main pipeline contains stages meant only for real packets, such as conntrack, NAT, redirect ownership, FTP/SMTP stream handling, and execution forwarding,
- `ExecutionStage` is part of the cloned main pipeline and owns a real execution sender,
- multiple stages need explicit `dpi.decrypted` guards to avoid doing the wrong thing,
- policy and IPS results are tied to `PacketContext`, making TLS plaintext inspection look more complete than it really is.

The correct model is closer to the runtime reality: TLS MITM creates two TLS sessions, decrypts bytes, runs security inspection on plaintext flow data, then writes the approved plaintext into the opposite TLS stream where it is re-encrypted.

## Non-Goals

This design does not implement Palo Alto PAN-OS Single Pass Parallel Processing.

This design does not rewrite the full packet dataplane.

This design does not add QUIC or HTTP/3 decryption.

This design does not add new TLS policy UI.

This design does not change transparent redirect behavior, upstream egress binding, certificate forgery, ECH policy, or decryption mirror transport unless required to consume the new flow result.

This design does not remove `PacketContext` from the normal packet path.

## Baseline

The current TLS runtime already has useful pieces that remain:

- `MitmProxy` owns TLS interception and upstream/client TLS sessions.
- `InspectionRelay` reads plaintext chunks from one TLS stream, asks an inspector for a decision, writes approved bytes to the other stream, and records mirror data.
- `SessionMeta` carries session id, peer, server, original destination, SNI, ALPN, inbound/outbound mode, and client/server-side interfaces.
- `DpiContext` already has `decrypted`, source port, destination port, HTTP, DNS, TLS, and IPS metadata fields.
- `Ips::inspect_decrypted()` already supports IPS inspection without `PacketContext`.
- `IdentitySessionStore` can resolve user identity from source IP and time.
- `Conntrack` and `SessionManager` already create per-flow L4 session tasks for real packet flows.
- The current TCP L4 pipeline is not a general HTTP pipeline yet. It does not own TLS decryption or HTTP state for HTTPS sessions.

The new work keeps this baseline and replaces the synthetic packet bridge. It must not add a new path that reinjects decrypted bytes into a virtual interface. Decrypted bytes either stay in the current TLS relay path or, in the L4 target model, move directly from a TLS L4 stage into an HTTP L4 stage.

## Target Architecture

TLS plaintext gets a dedicated flow path:

```text
MitmProxy
  -> InspectionRelay
    -> DecryptedTrafficInspector
      -> DecryptedFlowContext
      -> DecryptedFlowPipeline
        -> DecryptedDpiStage
        -> DecryptedIpsStage
        -> DecryptedPolicyStage
      -> InspectionDecision
    -> write approved plaintext to opposite TLS stream
    -> DecryptionMirror records approved or dropped plaintext according to config
```

The normal `DataPipeline` stays only for real packets:

```text
PacketContext
  -> Validation
  -> Metrics
  -> Ownership
  -> Identity
  -> Conntrack
  -> DPI
  -> TLS/DNS/IPS/NAT/Policy
  -> Execution
```

There must be no call from TLS decrypted inspection into `Stage::process()` on the main packet pipeline.

The target L4 architecture is:

```text
PacketContext
  -> Conntrack
  -> SessionManager
    -> TCP L4 session task
      -> TlsL4DecryptStage for HTTPS flows
        -> plaintext application chunks
        -> HttpL4Stage
          -> HTTP parser state
          -> HTTP policy and IPS decisions
      -> ReleaseAction
```

For plain HTTP, `HttpL4Stage` receives TCP payload bytes directly. For HTTPS, `HttpL4Stage` receives decrypted bytes from `TlsL4DecryptStage`. Both paths must use the same HTTP parser and HTTP policy logic after the decrypt boundary.

## Domain Model

### `DecryptedFlowContext`

`DecryptedFlowContext` is the first-class model for plaintext inspection. It is a flow chunk, not a packet.

Required fields:

- `payload: Vec<u8>`
- `direction: Direction`
- `session: SessionMeta`
- `arrival_time: SystemTime`
- `src: SocketAddr`
- `dst: SocketAddr`
- `source_interface: Option<String>`
- `identity: Option<IdentityContext>`
- `dpi: DpiContext`
- `warnings: Vec<String>`

For `Direction::ClientToServer`, `src` is `session.peer` and `dst` is `session.server`.

For `Direction::ServerToClient`, `src` is `session.server` and `dst` is `session.peer`.

`source_interface` is selected from `SessionMeta::source_interface_for_direction(direction)`.

`dpi.decrypted` must always be true for contexts created by TLS plaintext inspection.

### `DecryptedFlowOutcome`

`DecryptedFlowOutcome` describes what a stage decided:

```rust
pub enum DecryptedFlowOutcome {
    Continue,
    Drop { reason: String },
}
```

The pipeline stops on `Drop` and maps it to `InspectionDisposition::Drop`.

### `DecryptedFlowStage`

`DecryptedFlowStage` is separate from packet `Stage`:

```rust
#[tonic::async_trait]
pub trait DecryptedFlowStage: Send + Sync {
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome;
}
```

It does not receive an `ExecutionSender`, cannot emit `ExecutionItem`, and cannot forward packets.

`DecryptedFlowStage` is the phase-one plaintext inspection boundary. It is not the final L4 API. Any later `TlsL4DecryptStage` must keep the same rule: it may return plaintext chunks and decisions, but it must not construct `PacketContext` and must not write to TUN.

### `DecryptedFlowPipeline`

`DecryptedFlowPipeline` owns an ordered list of flow stages and runs them until all continue or one drops.

The initial production stages are:

1. `DecryptedDpiStage`
2. `DecryptedIpsStage`
3. `DecryptedPolicyStage`

Logging and mirror remain in `InspectionRelay` unless a test shows that moving them into a flow stage is cleaner. `InspectionRelay` already has the session metadata needed to emit decrypted classification and IPS events.

## L4 TLS-to-HTTP Handoff

The L4 target model needs a stateful TLS component, not a stateless `decrypt(payload) -> plaintext` helper. TLS decryption needs handshake state, negotiated keys, record sequence state, peer direction, SNI, ALPN, and session metadata.

The current `L4Stage::on_bytes()` API is synchronous. Full TLS MITM cannot perform upstream/client network handshakes directly inside that method. The later L4 implementation must either add an async L4 boundary or use a session-local TLS worker/channel owned by the L4 session task.

The L4 handoff contract is:

```rust
pub struct L4PlaintextChunk {
    pub payload: Vec<u8>,
    pub direction: Direction,
    pub app_proto: AppProto,
    pub dpi: DpiContext,
}
```

`TlsL4DecryptStage` receives encrypted TCP payload bytes from `SessionManager::on_bytes()`. When enough TLS state exists, it returns one or more `L4PlaintextChunk` values. If the negotiated application protocol is HTTP-compatible, those chunks are handed to `HttpL4Stage` in the same per-flow L4 task.

The L4 TLS stage must preserve:

- session identity from conntrack,
- client and server endpoints,
- original destination,
- ingress and egress interface metadata,
- SNI,
- ALPN,
- client identity,
- direction.

The L4 TLS stage must not:

- synthesize Ethernet/IP/TCP headers,
- call `PacketContext::from_raw()` for decrypted payloads,
- send decrypted payloads to `TunForwarder`,
- call packet `Stage::process()` for decrypted payloads,
- run NAT or conntrack again for decrypted payloads.

`DecryptedFlowPipeline` remains useful as the phase-one implementation and as a reusable plaintext inspection engine. When the L4 TLS stage exists, it can call the same plaintext DPI, IPS, and policy logic through a small adapter, then pass allowed HTTP payloads to `HttpL4Stage`.

## DPI Without Synthetic Packets

`DpiClassifier` currently has useful session buffering, but `inspect_packet()` extracts flow identity and payload from `SlicedPacket`.

To reuse the buffering without fake packets, add a payload-based method:

```rust
pub fn inspect_flow_payload(
    &self,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> InspectResult
```

`inspect_packet()` becomes a wrapper that extracts the real packet flow and calls `inspect_flow_payload()`.

`DecryptedDpiStage` calls `inspect_flow_payload()` using endpoints from `DecryptedFlowContext`.

`DecryptedDpiStage` must preserve metadata already seeded by `InspectionRelay`, especially:

- `decrypted`,
- `src_port`,
- `dst_port`,
- existing app protocol if the new classifier still needs more bytes,
- existing HTTP metadata when new classification does not improve it.

## IPS Without Synthetic Packets

`DecryptedIpsStage` uses `Ips::inspect_decrypted()` directly.

Verdict mapping:

- `IpsVerdict::Allow` -> continue.
- `IpsVerdict::Alert(matches)` -> set `ctx.dpi.ips_match` from the first match with `blocked = false`, push warning messages, continue.
- `IpsVerdict::Block(match)` -> set `ctx.dpi.ips_match` with `blocked = true`, push warning message, drop.

The inspected app protocol comes from `ctx.dpi.app_proto`.

The inspected ports come from `ctx.src.port()` and `ctx.dst.port()`.

## Policy Without Synthetic Packets

Current `PolicyEvalContext` depends on `SlicedPacket`. That prevents policy evaluation on plaintext flow data without building a fake packet.

Policy evaluation must be refactored to use explicit policy fields:

```rust
pub struct PolicyFlowFields {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub ip_ver: IpVer,
    pub protocol: Protocol,
    pub src_port: Option<Port>,
    pub dst_port: Option<Port>,
}
```

`PolicyEvalContext` then contains:

- `flow: PolicyFlowFields`
- `arrival: &ArrivalInfo`
- `dns: Option<&DnsEvalContext>`
- `dpi: Option<&DpiContext>`
- `identity: Option<&IdentityContext>`

`PolicyEvalStage` on the packet path builds `PolicyFlowFields` from the real `PacketContext`.

`DecryptedPolicyStage` builds `PolicyFlowFields` from `DecryptedFlowContext`.

The policy evaluator must preserve existing match semantics:

- source and destination IP,
- IP version,
- protocol,
- source and destination port,
- hour and day of week,
- DNSSEC status,
- auth state,
- identity user,
- identity group,
- application protocol.

DNSSEC checks are not run for decrypted TLS plaintext in this design because DNS over TLS/HTTPS plaintext handling is not currently modeled as DNS request/response validation. If a decrypted flow is classified as DNS and DNSSEC policy support is later needed, that should be added as a separate design.

## Zone Resolution

`DecryptedPolicyStage` uses the same zone resolver concept as packet policy evaluation.

For a decrypted flow:

- source interface is `ctx.source_interface`,
- destination IP is `ctx.dst.ip()`,
- zone pair is resolved with `zone_resolver.resolve(source_interface, dst_ip)`.

If the source interface is missing or no zone pair is found, behavior must match current packet policy behavior: log `policy.zone_pair.missing` and continue. That preserves current development fallback semantics and avoids broad policy behavior changes in this refactor.

## Identity

`DecryptedFlowContext` resolves identity at context creation:

- use `meta.peer.ip()` as the identity source,
- use `arrival_time`,
- call `resolve_identity(&identity_sessions, meta.peer.ip(), arrival_time)`.

For `ServerToClient`, identity remains the client identity from `meta.peer`, not the server IP. This matches the session user model: the decrypted TLS flow belongs to the client session even when the chunk direction is server-to-client.

## Decrypted Traffic Inspector

The existing `DecryptedTrafficInspector` trait can remain as the boundary used by `InspectionRelay`.

The production implementation changes from `DecryptedChainInspector<P>` to `DecryptedFlowInspector`.

`DecryptedFlowInspector` owns:

- `DecryptedFlowPipeline`,
- `Arc<DpiClassifier>`,
- `Arc<IdentitySessionStore>`,
- policy/zone dependencies needed by `DecryptedPolicyStage`.

`inspect()` behavior:

1. Build `DecryptedFlowContext` from payload, seed `DpiContext`, direction, `SessionMeta`, arrival time, identity, and source interface.
2. Run `DecryptedFlowPipeline`.
3. Return `InspectionDecision` with:
   - `Forward` and possibly modified payload when all stages continue,
   - `Drop` when any stage drops,
   - final `DpiContext`,
   - final payload.

`close_session()` removes both client-to-server and server-to-client DPI flow state by calling `DpiClassifier::remove_session()` with both endpoint directions, as the current code does.

## Main Wiring

`main.rs` must stop passing `pipeline.clone()` into TLS decrypted inspection.

Instead it builds:

- normal `DataPipeline` for real packets,
- `DecryptedFlowPipeline` for TLS plaintext.

`MitmProxyConfig.decrypted_inspector` receives:

```rust
Arc::new(DecryptedFlowInspector::new(...))
```

No TLS plaintext inspector should own or receive `ExecutionStage`, `ExecutionSender`, or a generic packet `Stage`.

## Deletion and Compatibility

Remove these synthetic packet functions from TLS plaintext inspection:

- `build_packet_context()`
- `build_tcp_packet()`
- `transport_payload()` if no longer needed

Remove tests that only prove synthetic packet construction works. Replace them with tests that prove plaintext inspection works without `PacketContext`.

`NoopDecryptedInspector` remains for relay tests.

The normal packet path and packet IPS tests may keep their own packet builders because those tests model real packet processing, not decrypted TLS plaintext.

## Observability

Existing decrypted events remain:

- `tls.decrypted_traffic.classified`
- `DecryptedIpsMatch`
- decryption mirror frames

Add a structured warning event or log when decrypted policy drops:

- `tls.decrypted.policy.dropped`

Add a structured trace when the decrypted flow pipeline starts and completes:

- `tls.decrypted.flow.inspect.started`
- `tls.decrypted.flow.inspect.completed`

These logs must include session id, peer, server, direction, mode, SNI, app protocol when known, and drop reason when dropped.

## Testing Strategy

Required unit tests:

- `DpiClassifier::inspect_flow_payload()` classifies HTTP plaintext without a packet.
- `DpiClassifier::inspect_packet()` still classifies packet payloads after the refactor.
- `DecryptedFlowContext` sets endpoints and source interface correctly for client-to-server.
- `DecryptedFlowContext` sets endpoints and source interface correctly for server-to-client.
- `DecryptedFlowContext` resolves identity from `meta.peer.ip()` for both directions.
- `DecryptedDpiStage` marks all contexts as decrypted and preserves seeded ports.
- `DecryptedIpsStage` allows clean plaintext.
- `DecryptedIpsStage` records alert metadata without dropping.
- `DecryptedIpsStage` drops blocked signatures.
- `PolicyEvaluator` still evaluates existing packet-derived policy fields through `PolicyFlowFields`.
- `DecryptedPolicyStage` drops when the policy engine returns `Drop`.
- `DecryptedPolicyStage` continues when policy returns `Allow`.
- `DecryptedFlowInspector` returns `Forward` for clean HTTP plaintext.
- `DecryptedFlowInspector` returns `Drop` for blocked IPS plaintext.
- A regression test proves TLS plaintext inspection does not call `ExecutionStage` or send an `ExecutionItem`.
- A future L4 handoff test proves a TLS L4 decrypt stage can pass HTTP plaintext to an HTTP L4 stage without creating `PacketContext`.
- A future L4 handoff test proves decrypted HTTP chunks are never sent to `TunForwarder`.

Required integration or focused runtime tests:

- HTTPS request through the vagrant topology still returns content.
- A decrypted IPS signature can block a TLS request.
- Logs still show decrypted classification and IPS match.
- No synthetic `RGDM`-mixed bytes or fake packet bytes are observed in client output.

## Acceptance Criteria

The change is complete when:

- TLS decrypted inspection no longer calls the main packet pipeline.
- TLS decrypted inspection no longer builds fake Ethernet/IP/TCP packets.
- `DecryptedFlowContext` is the model used by plaintext DPI, IPS, and policy.
- Policy evaluation works for both real packet contexts and decrypted flow contexts.
- `ExecutionStage` is impossible to reach from TLS plaintext inspection.
- The design explicitly preserves the later path from TLS L4 decryption to HTTP L4 parsing without virtual-interface reinjection.
- Existing packet path tests still pass.
- Existing TLS MITM behavior still works for a basic HTTPS request.
