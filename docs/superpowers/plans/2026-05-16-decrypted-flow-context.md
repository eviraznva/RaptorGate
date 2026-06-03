# Full L4 TLS Application Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move TLS application inspection into the per-flow TCP L4 pipeline so HTTPS and SMTP-over-TLS bytes are decrypted, inspected, handed to the correct application L4 state, and re-emitted as legitimate encrypted TCP traffic without transparent redirect or synthetic plaintext packets.

**Architecture:** `SessionManager` owns TCP flows. HTTP on port 80 goes directly to `HttpL4Stage`; HTTPS on port 443 goes to `TlsHttpL4Stage`, which owns a session-local TLS MITM worker and feeds approved plaintext to `DecryptedFlowPipeline` and then `HttpL4Stage`. SMTP on ports 25/587 goes to `SmtpL4Stage`; accepted STARTTLS upgrades the same flow into TLS and then returns decrypted SMTP plaintext to `SmtpL4Stage`. Implicit SMTPS on port 465 goes directly to `TlsSmtpL4Stage`. The normal `DataPipeline` remains for real packets only. Decrypted plaintext never becomes `PacketContext`.

**Tech Stack:** Rust 2024, Tokio, tokio-rustls, rustls, existing conntrack/session manager, existing TLS decision/cert/decrypted-flow modules, existing vagrant test environment.

**Design Spec:** `docs/superpowers/specs/2026-05-16-decrypted-flow-context-design.md`

---

## Current Branch Baseline

The earlier packet-free plaintext work is already present and must not be reimplemented:

- `crates/raptorgate/src/tls/decrypted_flow.rs` exists and provides `DecryptedFlowContext`, `DecryptedFlowPipeline`, `DecryptedDpiStage`, `DecryptedIpsStage`, `DecryptedPolicyStage`, and `DecryptedFlowInspector`.
- `crates/raptorgate/src/main.rs` already constructs `DecryptedFlowInspector` for the old MITM runtime.
- `crates/raptorgate/src/l4/http.rs` exists and starts `HttpL4Stage`.
- `crates/raptorgate/src/l4/tls.rs` exists and starts `TlsInspectionService` plus `TlsHttpL4Stage`.
- `crates/raptorgate/src/l4/factory.rs` already starts routing port 80 to HTTP and SMTP ports to SMTP.
- SMTP routing currently treats port 465 as plaintext SMTP and does not support STARTTLS handoff on ports 25/587.

This plan starts from that baseline and finishes the actual target: port 443 HTTPS, port 465 SMTPS, and STARTTLS SMTP on ports 25/587 must be owned by the L4 TLS pipeline when TLS is active.

---

## File Structure

**Create**
- `crates/raptorgate/src/l4/tcp_endpoint.rs`: session-local async TCP byte endpoint for L4 TLS. It receives encrypted bytes from conntrack payload delivery and returns generated encrypted TCP bytes to `SessionManager`.
- `crates/raptorgate/src/tls/l4_inspection.rs`: production TLS L4 inspection service. It reuses cert forging, decision engine, generic dual-session helpers, `InspectionRelay`, `DecryptedFlowPipeline`, and `HttpL4Stage`.
- `crates/raptorgate/tests/l4_tls_inspection.rs`: integration tests for L4-owned HTTPS handoff without synthetic plaintext packets.
- `crates/raptorgate/tests/l4_smtp_tls_inspection.rs`: integration tests for implicit SMTPS and SMTP STARTTLS handoff without synthetic plaintext packets.

**Modify**
- `crates/raptorgate/src/l4.rs`: export `tcp_endpoint`.
- `crates/raptorgate/src/l4/stage.rs`: make L4 stage execution async and add generated-output outcomes.
- `crates/raptorgate/src/l4/factory.rs`: route port 443 to TLS HTTP, port 465 to TLS SMTP, and ports 25/587 to STARTTLS-capable SMTP.
- `crates/raptorgate/src/l4/http.rs`: keep HTTP parser state as the shared target for plain HTTP and decrypted HTTPS.
- `crates/raptorgate/src/l4/tls.rs`: replace the current trait-only TLS handoff with production TLS-to-application wrappers around `tls::l4_inspection`.
- `crates/raptorgate/src/dpi/smtp_l4_stage.rs`: detect accepted STARTTLS and hand the encrypted part of the session to TLS inspection.
- `crates/raptorgate/src/l4/release.rs`: represent generated encrypted packets in post-session release.
- `crates/raptorgate/src/conntrack/session_manager.rs`: await async L4 stages, consume L4-owned original packets, and release generated encrypted packets.
- `crates/raptorgate/src/tls/dual_session.rs`: make accept/connect helpers generic over async IO, not hardcoded to `tokio::net::TcpStream`.
- `crates/raptorgate/src/tls/inspection_relay.rs`: keep relay generic over async IO and expose a constructor usable from L4.
- `crates/raptorgate/src/main.rs`: stop installing transparent redirect and stop spawning `MitmProxy` for managed outbound HTTPS.
- `crates/raptorgate/src/daemon.rs`: pass TLS L4 dependencies into `TcpL4PipelineFactory::new_application_router(...)`.
- `vagrant/deploy.sh`: no functional change required unless smoke test discovers deployment still installs redirect rules.

**Do not modify**
- backend UI/protobuf.
- unrelated NAT, DNSSEC, identity, ML, or SMTP policy behavior except for changes required by STARTTLS upgrade handling.

---

## Task 1: Prove Current TLS Application Routing Is Not Complete

**Files:**
- Modify: `crates/raptorgate/src/l4/factory.rs`

- [ ] **Step 1: Add a failing test for HTTPS routing**

Add this test to the existing `#[cfg(test)]` module in `crates/raptorgate/src/l4/factory.rs`:

```rust
#[test]
fn application_router_selects_tls_http_for_https() {
    let factory = TcpL4PipelineFactory::new_application_router(smtp_policy_retriever());

    assert!(matches!(
        factory.build_for_entry(&sample_tcp_entry_with_ports(12345, 443)),
        TcpSessionPipeline::TlsHttp(_)
    ));
}
```

Run:

```bash
cargo test -p ngfw l4::factory::tests::application_router_selects_tls_http_for_https
```

Expected: FAIL because `TcpSessionPipeline::TlsHttp` does not exist or port 443 still returns passthrough.

Add a second failing test for implicit SMTPS:

```rust
#[test]
fn application_router_selects_tls_smtp_for_smtps() {
    let factory = TcpL4PipelineFactory::new_application_router(smtp_policy_retriever());

    assert!(matches!(
        factory.build_for_entry(&sample_tcp_entry_with_ports(12345, 465)),
        TcpSessionPipeline::TlsSmtp(_)
    ));
}
```

Run:

```bash
cargo test -p ngfw l4::factory::tests::application_router_selects_tls_smtp_for_smtps
```

Expected: FAIL because port 465 currently returns plaintext `Smtp`.

- [ ] **Step 2: Do not fix this test yet**

Leave this test failing until Tasks 2 through 6 provide the real dependencies for `TlsHttp`.

---

## Task 2: Make the L4 Stage Boundary Async and Capable of Emitting Generated Packets

**Files:**
- Modify: `crates/raptorgate/src/l4/stage.rs`
- Modify: `crates/raptorgate/src/l4/factory.rs`
- Modify: `crates/raptorgate/src/l4/http.rs`
- Modify: `crates/raptorgate/src/l4/tls.rs`
- Modify: `crates/raptorgate/src/l4/chain.rs`
- Modify: `crates/raptorgate/src/dpi/smtp_l4_stage.rs`
- Modify: `crates/raptorgate/src/l4/noop.rs`

- [ ] **Step 1: Add output types to `l4/stage.rs`**

Replace `L4Outcome` in `crates/raptorgate/src/l4/stage.rs` with:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Emit {
    pub dir: Direction,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Outcome {
    Continue,
    Forward(Vec<PacketId>),
    Drop(Vec<PacketId>),
    Emit(Vec<L4Emit>),
    ForwardAndEmit { forward: Vec<PacketId>, emit: Vec<L4Emit> },
    Terminate { reason: TerminateReason, reset: bool },
}
```

`Drop(Vec<PacketId>)` means the L4 stage consumed those original packets and they must not be released to the normal packet path.

- [ ] **Step 2: Make the trait async**

Change `L4Stage` to:

```rust
#[tonic::async_trait]
pub trait L4Stage: Send {
    type Ctx: Send;

    fn protocol(&self) -> AppProto;

    async fn on_session_open(&mut self, ctx: &mut Self::Ctx) -> L4Outcome;

    async fn on_bytes(
        &mut self,
        ctx: &mut Self::Ctx,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome;

    async fn on_session_close(&mut self, ctx: &mut Self::Ctx, reason: CloseReason);
}
```

- [ ] **Step 3: Update stage implementations**

For each existing L4 implementation, add `#[tonic::async_trait]` to the impl and change methods to `async fn`.

The behavior must remain unchanged:

- `HttpL4Stage::on_bytes()` returns `L4Outcome::Forward(vec![packet_id])`.
- SMTP stage returns the same outcome it returned before.
- noop stages still forward.
- force terminate still terminates.

- [ ] **Step 4: Update L4 chain and factory dispatch**

Every call through `TcpSessionPipeline`, `L4Chain`, and tests must `.await` async stage methods.

Run:

```bash
cargo test -p ngfw l4::
```

Expected: PASS except the intentional failing HTTPS and SMTPS routing tests from Task 1.

- [ ] **Step 5: Commit**

```bash
git add crates/raptorgate/src/l4 crates/raptorgate/src/dpi/smtp_l4_stage.rs
git commit -m "refactor(l4): make session stages async"
```

---

## Task 3: Add Managed TCP Endpoint for L4 TLS

**Files:**
- Create: `crates/raptorgate/src/l4/tcp_endpoint.rs`
- Modify: `crates/raptorgate/src/l4.rs`
- Modify: `crates/raptorgate/src/conntrack/session_manager.rs`

- [ ] **Step 1: Add unit tests for endpoint byte flow**

Create `crates/raptorgate/src/l4/tcp_endpoint.rs` with tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::tuple::Direction;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn endpoint_reads_admitted_encrypted_bytes() {
        let (endpoint, handle) = L4TcpEndpoint::new();

        handle.admit(Direction::Original, b"client tls".to_vec()).await.unwrap();
        drop(handle);

        let mut reader = endpoint.reader;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"client tls");
    }

    #[tokio::test]
    async fn endpoint_write_returns_generated_ciphertext() {
        let (endpoint, mut handle) = L4TcpEndpoint::new();

        let mut writer = endpoint.writer;
        writer.write_all(b"server tls").await.unwrap();
        writer.flush().await.unwrap();

        let emitted = handle.next_emitted().await.unwrap();
        assert_eq!(emitted.dir, Direction::Reply);
        assert_eq!(emitted.payload, b"server tls");
    }
}
```

Run:

```bash
cargo test -p ngfw l4::tcp_endpoint
```

Expected: FAIL because the endpoint does not exist.

- [ ] **Step 2: Implement endpoint types**

Implement these public types:

```rust
pub struct L4TcpEndpoint {
    pub reader: L4TcpReadHalf,
    pub writer: L4TcpWriteHalf,
}

#[derive(Clone)]
pub struct L4TcpEndpointHandle {
    inbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    emitted_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<L4Emit>>>,
}
```

`L4TcpReadHalf` implements `tokio::io::AsyncRead` by draining chunks received through an mpsc channel.

`L4TcpWriteHalf` implements `tokio::io::AsyncWrite` by sending `L4Emit { dir: Direction::Reply, payload }` through an mpsc channel.

For server-to-client TLS, construct a second endpoint with writer direction `Direction::Original` when needed. Do not encode direction globally in `L4TcpEndpoint::new()` unless the tests require it.

- [ ] **Step 3: Export the module**

In `crates/raptorgate/src/l4.rs`, add:

```rust
pub mod tcp_endpoint;
pub use tcp_endpoint::{L4TcpEndpoint, L4TcpEndpointHandle, L4TcpReadHalf, L4TcpWriteHalf};
```

- [ ] **Step 4: Run tests**

```bash
cargo test -p ngfw l4::tcp_endpoint
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/raptorgate/src/l4.rs crates/raptorgate/src/l4/tcp_endpoint.rs
git commit -m "feat(l4): add managed tcp byte endpoint"
```

---

## Task 4: Teach SessionManager to Consume Original Packets and Emit Generated Ciphertext

**Files:**
- Modify: `crates/raptorgate/src/conntrack/session_manager.rs`
- Modify: `crates/raptorgate/src/l4/release.rs`
- Modify: `crates/raptorgate/src/l4/reset.rs` if generated TCP packet helpers need shared code.

- [ ] **Step 1: Add a session manager test for consumed packets**

In `crates/raptorgate/src/conntrack/session_manager.rs`, add a test that installs a TCP factory whose first payload returns:

```rust
L4Outcome::Drop(vec![packet_id])
```

The test should admit one TCP packet and assert that `release_rx` receives:

```rust
ReleaseAction::Drop {
    packet_id,
    reason: DropReason::StageDropped,
    ..
}
```

Run:

```bash
cargo test -p ngfw conntrack::session_manager::tests::l4_drop_consumes_original_packet
```

Expected: FAIL because `L4Outcome::Drop` is not handled.

- [ ] **Step 2: Add generated packet release representation**

Extend `ReleaseAction` if needed:

```rust
pub enum ReleaseAction {
    Forward { packet: PacketContext },
    Drop { packet_id: PacketId, reason: DropReason, temp_dst_port: Option<u16> },
}
```

If generated encrypted bytes are converted to `PacketContext` inside `SessionManager`, keep `ReleaseAction::Forward`. Do not add a plaintext release action.

- [ ] **Step 3: Handle `Drop` and `Emit` outcomes**

In the session task outcome match:

- `Drop(ids)` sends `ReleaseAction::Drop` for each id with `DropReason::StageDropped`.
- `Emit(items)` builds generated encrypted TCP packets and sends `ReleaseAction::Forward`.
- `ForwardAndEmit` performs both.
- `Terminate` drops all pending packets and invalidates conntrack as today.

The generated packet builder must use real flow metadata from `SessionContext::entry()`. It must not use decrypted plaintext as payload. Payload in `L4Emit` is encrypted TLS ciphertext.

- [ ] **Step 4: Add a generated ciphertext test**

Add a test where an L4 stage returns:

```rust
L4Outcome::ForwardAndEmit {
    forward: vec![],
    emit: vec![L4Emit {
        dir: Direction::Reply,
        payload: b"encrypted response".to_vec(),
    }],
}
```

Assert that the release receiver gets a `ReleaseAction::Forward { packet }` and that the generated packet payload contains `encrypted response`.

Run:

```bash
cargo test -p ngfw conntrack::session_manager::tests::l4_emit_releases_generated_ciphertext_packet
```

Expected: PASS after implementation.

- [ ] **Step 5: Run session manager tests**

```bash
cargo test -p ngfw conntrack::session_manager
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/raptorgate/src/conntrack/session_manager.rs crates/raptorgate/src/l4/release.rs crates/raptorgate/src/l4/reset.rs
git commit -m "feat(l4): let sessions emit generated tcp traffic"
```

---

## Task 5: Make TLS Dual Session Helpers Work With Generic Async IO

**Files:**
- Modify: `crates/raptorgate/src/tls/dual_session.rs`
- Modify: `crates/raptorgate/src/tls/mitm_proxy.rs` for compile compatibility only.

- [ ] **Step 1: Add generic IO tests**

In `crates/raptorgate/src/tls/dual_session.rs`, add a test using `tokio::io::duplex`:

```rust
#[tokio::test]
async fn accept_client_tls_works_with_generic_async_io() {
    let (cert_pem, key_pem) = make_localhost_cert();
    let server_config = crate::tls::rustls_config::build_server_config_from_pem(&cert_pem, &key_pem).unwrap();
    let client_config = make_client_config_trusting(&cert_pem);
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        accept_client_tls(AcceptParams {
            stream: server_io,
            server_config,
        })
        .await
    });

    let server_name: rustls::pki_types::ServerName<'_> = "localhost".try_into().unwrap();
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let client = connector.connect(server_name, client_io).await;

    assert!(client.is_ok());
    assert!(server.await.unwrap().is_ok());
}
```

Run:

```bash
cargo test -p ngfw tls::dual_session::tests::accept_client_tls_works_with_generic_async_io
```

Expected: FAIL because `AcceptParams` is hardcoded to `TcpStream`.

- [ ] **Step 2: Make params generic**

Change the params and helpers to:

```rust
pub struct AcceptParams<S> {
    pub stream: S,
    pub server_config: Arc<ServerConfig>,
}

pub struct ConnectParams<S> {
    pub stream: S,
    pub client_config: Arc<ClientConfig>,
    pub server_name: String,
}

pub async fn accept_client_tls<S>(params: AcceptParams<S>) -> anyhow::Result<ServerTlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let acceptor = TlsAcceptor::from(params.server_config);
    acceptor.accept(params.stream).await.context("TLS accept from client failed")
}

pub async fn connect_to_server<S>(params: ConnectParams<S>) -> anyhow::Result<ClientTlsStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let server_name = params.server_name.clone().try_into().context("Invalid server name for TLS connection")?;
    let connector = TlsConnector::from(params.client_config);
    connector.connect(server_name, params.stream).await.context("TLS connect to server failed")
}
```

Update existing `mitm_proxy.rs` call sites from `tcp_stream` to `stream`.

- [ ] **Step 3: Run TLS helper tests**

```bash
cargo test -p ngfw tls::dual_session
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/raptorgate/src/tls/dual_session.rs crates/raptorgate/src/tls/mitm_proxy.rs
git commit -m "refactor(tls): accept generic async io for dual sessions"
```

---

## Task 6: Implement Production TLS L4 Inspection Service

**Files:**
- Create: `crates/raptorgate/src/tls/l4_inspection.rs`
- Modify: `crates/raptorgate/src/tls/mod.rs`
- Modify: `crates/raptorgate/src/l4/tls.rs`
- Modify: `crates/raptorgate/src/l4/http.rs`
- Modify: `crates/raptorgate/src/dpi/smtp_l4_stage.rs`

- [ ] **Step 1: Add L4 TLS service tests**

Create `crates/raptorgate/src/tls/l4_inspection.rs` with these tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::tuple::Direction;
    use crate::l4::http::HttpL4Stage;
    use crate::l4::stage::L4Outcome;

    #[tokio::test]
    async fn service_bypasses_non_tls_payload() {
        let mut service = test_service();
        let mut ctx = test_session_context(443);

        let out = service.on_encrypted_bytes(
            &mut ctx,
            PacketId::next(),
            Direction::Original,
            0,
            b"GET / HTTP/1.1\r\n\r\n",
            &mut HttpL4Stage::new(),
        ).await;

        assert!(matches!(out, L4Outcome::Forward(_)));
    }

    #[tokio::test]
    async fn service_drops_when_decision_engine_blocks() {
        let mut service = test_service_with_block_decision();
        let mut ctx = test_session_context(443);

        let out = service.on_encrypted_bytes(
            &mut ctx,
            PacketId::next(),
            Direction::Original,
            0,
            tls_client_hello_for("blocked.example"),
            &mut HttpL4Stage::new(),
        ).await;

        assert!(matches!(out, L4Outcome::Terminate { .. } | L4Outcome::Drop(_)));
    }
}
```

Use existing TLS test helpers where available. If no reusable ClientHello helper exists, move the existing helper from `tls::mitm_proxy` tests into a private test helper in this module.

Run:

```bash
cargo test -p ngfw tls::l4_inspection
```

Expected: FAIL because the module does not exist.

- [ ] **Step 2: Define service config**

Add:

```rust
pub struct TlsL4InspectionConfig {
    pub cert_forger: Arc<CertForger>,
    pub untrust_forger: Arc<CertForger>,
    pub decision_engine: Arc<TlsDecisionEngine>,
    pub decrypted_pipeline: DecryptedFlowPipeline,
    pub dpi_classifier: Arc<DpiClassifier>,
    pub identity_sessions: Arc<IdentitySessionStore>,
    pub decryption_mirror: Arc<DecryptionMirror>,
}

pub struct TlsL4InspectionService {
    config: Arc<TlsL4InspectionConfig>,
}
```

- [ ] **Step 3: Implement encrypted byte entrypoint**

Add:

```rust
impl TlsL4InspectionService {
    pub async fn on_encrypted_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
        http: &mut HttpL4Stage,
    ) -> L4Outcome {
        // Implementation fills this in during the step.
    }
}
```

Required behavior:

- If payload is not TLS ClientHello and no TLS session is active, return `L4Outcome::Forward(vec![packet_id])`.
- If decision is bypass, return `L4Outcome::Forward(vec![packet_id])`.
- If decision is block, return `L4Outcome::Drop(vec![packet_id])` or terminate with reset.
- If decision is intercept, consume original packet id and feed bytes into the managed TLS worker.
- Approved plaintext from the worker must run through `DecryptedFlowPipeline`.
- Approved HTTP plaintext must call `http.inspect_plaintext(ctx, plaintext)`.
- Generated TLS ciphertext must return through `L4Outcome::Emit` or `ForwardAndEmit`.

- [ ] **Step 4: Wire TLS application stages to the production service**

In `crates/raptorgate/src/l4/tls.rs`, replace the current generic test service shape with production application wrappers:

```rust
pub struct TlsHttpL4Stage {
    tls: TlsL4InspectionService,
    http: HttpL4Stage,
}

pub struct TlsSmtpL4Stage<ZR> {
    tls: TlsL4InspectionService,
    smtp: SmtpL4Stage<ZR>,
}
```

`on_bytes()` calls:

```rust
self.tls
    .on_encrypted_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload, &mut self.http)
    .await
```

`TlsSmtpL4Stage` uses the same TLS service, but passes approved plaintext to `SmtpL4Stage`.

Keep a test-only static inspection service only if needed under `#[cfg(test)]`; production should use `TlsL4InspectionService`.

- [ ] **Step 5: Export module**

In `crates/raptorgate/src/tls/mod.rs`, add:

```rust
pub mod l4_inspection;
```

Run:

```bash
cargo test -p ngfw tls::l4_inspection l4::http
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/raptorgate/src/tls/l4_inspection.rs crates/raptorgate/src/tls/mod.rs crates/raptorgate/src/l4/tls.rs crates/raptorgate/src/l4/http.rs crates/raptorgate/src/dpi/smtp_l4_stage.rs
git commit -m "feat(tls): add l4 inspection service"
```

---

## Task 7: Route HTTPS and SMTPS to TLS L4 Pipelines

**Files:**
- Modify: `crates/raptorgate/src/l4/factory.rs`
- Modify: `crates/raptorgate/src/daemon.rs`
- Modify: `crates/raptorgate/src/main.rs`

- [ ] **Step 1: Extend factory dependencies**

Change `TcpL4PipelineFactory::new_application_router(...)` to accept TLS dependencies:

```rust
pub fn new_application_router(
    smtp_policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
    tls_inspection: Arc<TlsL4InspectionConfig>,
) -> Self
```

Store both in `TcpFactoryKind::ApplicationRouter`.

- [ ] **Step 2: Add TLS pipeline variants**

Add:

```rust
TlsHttp(TlsHttpL4Stage),
TlsSmtp(TlsSmtpL4Stage<ZR>),
```

Update `protocol`, `on_session_open`, `on_bytes`, and `on_session_close` dispatch.

- [ ] **Step 3: Route HTTPS and SMTPS**

Change `build_for_entry()`:

```rust
if src == 465 || dst == 465 {
    TcpSessionPipeline::TlsSmtp(TlsSmtpL4Stage::new(
        TlsL4InspectionService::new(Arc::clone(tls)),
        SmtpL4Stage::new(Arc::clone(smtp)),
    ))
} else if matches!(src, 25 | 587) || matches!(dst, 25 | 587) {
    TcpSessionPipeline::Smtp(SmtpL4Stage::new(Arc::clone(smtp)))
} else if src == 80 || dst == 80 {
    TcpSessionPipeline::Http(HttpL4Stage::new())
} else if src == 443 || dst == 443 {
    TcpSessionPipeline::TlsHttp(TlsHttpL4Stage::new(TlsL4InspectionService::new(Arc::clone(tls))))
} else {
    TcpSessionPipeline::PassThrough(TcpPassThroughStage::default())
}
```

- [ ] **Step 4: Make Task 1 test pass**

Run:

```bash
cargo test -p ngfw l4::factory::tests::application_router_selects_tls_http_for_https
cargo test -p ngfw l4::factory::tests::application_router_selects_tls_smtp_for_smtps
```

Expected: PASS.

- [ ] **Step 5: Wire daemon dependencies**

In `DaemonV2::assemble_v2`, construct `TlsL4InspectionConfig` from existing static dependencies. Use the same dependencies currently used by `main.rs` for the old MITM runtime:

- `cert_forger`,
- `untrust_forger`,
- `decision_engine`,
- `DecryptedFlowPipeline`,
- `dpi_classifier`,
- `identity_sessions`,
- `decryption_mirror`.

If one of these dependencies is currently not present in `DaemonStaticDeps`, add it there rather than reaching around with globals.

- [ ] **Step 6: Run focused tests**

```bash
cargo test -p ngfw l4::factory tls::l4_inspection
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/raptorgate/src/l4/factory.rs crates/raptorgate/src/daemon.rs crates/raptorgate/src/main.rs
git commit -m "feat(l4): route tls applications to inspection pipeline"
```

---

## Task 8: Add SMTP STARTTLS Handoff

**Files:**
- Modify: `crates/raptorgate/src/dpi/smtp_l4_stage.rs`
- Modify: `crates/raptorgate/src/dpi/smtp_l4_session.rs`
- Modify: `crates/raptorgate/src/l4/factory.rs`
- Modify: `crates/raptorgate/src/l4/tls.rs`
- Create: `crates/raptorgate/tests/l4_smtp_tls_inspection.rs`

- [ ] **Step 1: Add STARTTLS upgrade tests**

Add a test that feeds a normal SMTP greeting and accepted STARTTLS negotiation through the SMTP L4 path:

```rust
#[tokio::test]
async fn smtp_starttls_upgrade_feeds_post_tls_plaintext_to_smtp_stage() {
    let harness = SmtpStartTlsHarness::new().await;

    let result = harness
        .session_with_starttls_then_mail_from("sender@example.test")
        .await;

    assert!(result.starttls_upgraded);
    assert_eq!(result.mail_from.as_deref(), Some("sender@example.test"));
    assert_eq!(result.synthetic_plaintext_packets, 0);
}
```

Run:

```bash
cargo test -p ngfw --test l4_smtp_tls_inspection smtp_starttls_upgrade_feeds_post_tls_plaintext_to_smtp_stage
```

Expected: FAIL until SMTP STARTTLS handoff exists.

- [ ] **Step 2: Detect accepted STARTTLS**

Teach `SmtpL4Stage` or `SmtpSession` to detect:

- client command `STARTTLS`,
- server success response `220`,
- the next client bytes beginning the TLS handshake.

When that transition is accepted, clear SMTP transaction state according to STARTTLS semantics and switch the session to TLS mode. Do not treat post-STARTTLS encrypted bytes as plaintext SMTP.

- [ ] **Step 3: Feed decrypted SMTP back into SMTP parser state**

Use the same TLS inspection service used by HTTPS. For post-STARTTLS chunks, approved plaintext must call the SMTP parser, not HTTP.

Required behavior:

- pre-STARTTLS plaintext SMTP is inspected by `SmtpL4Stage`,
- post-STARTTLS encrypted bytes are consumed by TLS inspection,
- decrypted SMTP bytes return to `SmtpL4Stage`,
- generated ciphertext is emitted through L4 outcomes,
- decrypted SMTP plaintext never becomes `PacketContext`.

- [ ] **Step 4: Add implicit SMTPS integration test**

Add:

```rust
#[tokio::test]
async fn smtps_port_465_decrypts_to_smtp_stage() {
    let harness = SmtpTlsHarness::new().await;

    let result = harness
        .implicit_tls_mail_from("sender@example.test")
        .await;

    assert_eq!(result.mail_from.as_deref(), Some("sender@example.test"));
    assert_eq!(result.synthetic_plaintext_packets, 0);
}
```

Run:

```bash
cargo test -p ngfw --test l4_smtp_tls_inspection
```

Expected: PASS after implementation.

- [ ] **Step 5: Commit**

```bash
git add crates/raptorgate/src/dpi/smtp_l4_stage.rs crates/raptorgate/src/dpi/smtp_l4_session.rs crates/raptorgate/src/l4/factory.rs crates/raptorgate/src/l4/tls.rs crates/raptorgate/tests/l4_smtp_tls_inspection.rs
git commit -m "feat(smtp): inspect tls smtp in l4 pipeline"
```

---

## Task 9: Remove Production Transparent Redirect Wiring

**Files:**
- Modify: `crates/raptorgate/src/main.rs`
- Modify: `crates/raptorgate/src/tls/redirect_manager.rs` only if startup references require cleanup.
- Modify: `crates/raptorgate/src/tls/transparent_redirect.rs` only if production exports require cleanup.

- [ ] **Step 1: Add a startup wiring regression test**

Add or extend a startup/daemon test to assert that SSL inspection enabled does not call `TransparentRedirect::install()` for managed outbound HTTPS.

If no startup test harness exists, add a narrow unit test around the startup builder function that creates TLS runtime components and expose a value:

```rust
assert_eq!(startup.tls_path, TlsStartupPath::L4Pipeline);
```

Run:

```bash
cargo test -p ngfw startup_tls_uses_l4_pipeline
```

Expected: FAIL until startup wiring is changed.

- [ ] **Step 2: Remove redirect install from production startup**

In `crates/raptorgate/src/main.rs`, remove the production call chain that:

- creates `TransparentRedirect`,
- calls `install()`,
- binds `MitmProxy`,
- spawns `proxy.serve()` for outbound HTTPS.

Do not delete the files yet if tests still cover them. The production path must not use them for managed HTTPS.

- [ ] **Step 3: Keep one TLS inspection path**

Make startup logs explicit:

```text
startup.tls_l4.enabled
```

There should be no normal startup log:

```text
startup.tls_redirect.installed
startup.mitm_proxy.spawned
```

for managed outbound HTTPS.

- [ ] **Step 4: Run TLS startup tests**

```bash
cargo test -p ngfw tls startup_tls_uses_l4_pipeline
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/raptorgate/src/main.rs crates/raptorgate/src/tls/redirect_manager.rs crates/raptorgate/src/tls/transparent_redirect.rs
git commit -m "refactor(tls): use l4 inspection as production path"
```

---

## Task 10: Integration Tests for Packet-Free HTTPS L4 Handoff

**Files:**
- Create: `crates/raptorgate/tests/l4_tls_inspection.rs`

- [ ] **Step 1: Add integration test for plaintext not becoming PacketContext**

Create:

```rust
#[tokio::test]
async fn tls_l4_plaintext_reaches_http_without_packet_context() {
    let harness = L4TlsHarness::new().await;

    let result = harness
        .https_request("www.example.test", b"GET / HTTP/1.1\r\nHost: www.example.test\r\n\r\n")
        .await;

    assert_eq!(result.http_host.as_deref(), Some("www.example.test"));
    assert_eq!(result.synthetic_plaintext_packets, 0);
}
```

`L4TlsHarness` should use in-process TLS endpoints and the real `TlsHttpL4Stage`; it must not use nft redirect or `MitmProxy::bind()`.

Run:

```bash
cargo test -p ngfw --test l4_tls_inspection tls_l4_plaintext_reaches_http_without_packet_context
```

Expected: FAIL until the harness is implemented.

- [ ] **Step 2: Implement harness**

The harness must:

- create a test CA/forger,
- create `TlsL4InspectionConfig`,
- create a `SessionContext` with TCP port 443,
- feed encrypted client bytes through `TlsHttpL4Stage::on_bytes()`,
- collect emitted encrypted bytes from `L4Outcome::Emit`,
- assert that only encrypted/generated bytes are released.

- [ ] **Step 3: Add block test**

Add:

```rust
#[tokio::test]
async fn tls_l4_ips_block_stops_generated_ciphertext() {
    let harness = L4TlsHarness::with_blocking_ips("UNION SELECT").await;

    let result = harness
        .https_request("www.example.test", b"GET /?q=UNION SELECT HTTP/1.1\r\nHost: www.example.test\r\n\r\n")
        .await;

    assert!(result.blocked);
    assert_eq!(result.generated_server_bytes, 0);
}
```

Run:

```bash
cargo test -p ngfw --test l4_tls_inspection
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/raptorgate/tests/l4_tls_inspection.rs
git commit -m "test(tls): cover l4 https plaintext handoff"
```

---

## Task 11: Full Test Suite

**Files:**
- No code changes unless tests reveal regressions.

- [ ] **Step 1: Run focused tests**

```bash
cargo test -p ngfw l4:: tls::l4_inspection tls::dual_session conntrack::session_manager
cargo test -p ngfw --test l4_tls_inspection --test l4_smtp_tls_inspection
```

Expected: PASS.

- [ ] **Step 2: Run full Rust tests outside sandbox if socket tests need it**

```bash
cargo test -p ngfw
```

Expected: PASS.

- [ ] **Step 3: Check for forbidden plaintext packet path**

Run:

```bash
rg -n "DecryptedChainInspector|PacketContext::from_raw|PacketContext::from_raw_full|TunForwarder|StageOutcome|ExecutionSender" crates/raptorgate/src/tls crates/raptorgate/src/l4
```

Expected:

- no match showing decrypted plaintext converted into `PacketContext`,
- no match showing decrypted plaintext sent to `TunForwarder`,
- no match showing TLS L4 plaintext calling packet `StageOutcome` or `ExecutionSender`.

Matches in tests for normal packet construction or generated encrypted TCP packets are acceptable only if the code path is not plaintext.

- [ ] **Step 4: Commit if any test fixes were needed**

```bash
git status --short
git add <changed-files>
git commit -m "test(tls): stabilize l4 inspection path"
```

Skip commit if no files changed.

---

## Task 12: Vagrant Test-Env Smoke

**Files:**
- No code changes unless smoke reveals deploy/runtime regressions.

- [ ] **Step 1: Deploy**

Run from repo root:

```bash
cd vagrant
./deploy.sh
```

Expected: deploy completes and CA is installed on h2.

- [ ] **Step 2: Verify forged certificate from h2**

Run:

```bash
cd vagrant
vagrant ssh h2 -c "openssl s_client -connect www.google.com:443 -servername www.google.com -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -fingerprint -sha256"
```

Expected output includes:

```text
subject=CN = www.google.com
issuer=CN = RaptorGate CA, O = RaptorGate
```

- [ ] **Step 3: Verify HTTPS content and no mixed debug/mirror bytes**

Run:

```bash
cd vagrant
vagrant ssh h2 -c "printf 'GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n' | openssl s_client -connect www.google.com:443 -servername www.google.com -quiet"
```

Expected:

- certificate verification succeeds against RaptorGate CA,
- response starts with HTTP headers,
- body contains Google HTML,
- output does not contain `RGDM`,
- output does not contain hex dump chunks from decryption mirror.

- [ ] **Step 4: Verify runtime path is L4, not redirect**

Run:

```bash
cd vagrant
vagrant ssh r1 -c "journalctl -u raptorgate --no-pager -n 300 | grep -E 'tls_l4|tls_redirect|mitm_proxy'"
```

Expected:

- includes L4 TLS startup/session logs,
- does not include `startup.tls_redirect.installed` for the active HTTPS path,
- does not include `startup.mitm_proxy.spawned` for the active HTTPS path.

- [ ] **Step 5: Commit smoke documentation if needed**

If the smoke commands need to be recorded for repeatability, update a test-env doc and commit:

```bash
git add docs
git commit -m "docs(tls): record l4 inspection smoke test"
```

Do not commit generated vagrant files.

---

## Final Acceptance Checklist

- [ ] Port 80 uses `HttpL4Stage`.
- [ ] Port 443 uses `TlsHttpL4Stage`.
- [ ] Port 465 uses `TlsSmtpL4Stage`.
- [ ] Ports 25/587 use `SmtpL4Stage` with STARTTLS upgrade support.
- [ ] `TlsHttpL4Stage` calls production `TlsL4InspectionService`.
- [ ] `TlsSmtpL4Stage` calls production `TlsL4InspectionService`.
- [ ] TLS plaintext runs through `DecryptedFlowPipeline`.
- [ ] Allowed HTTP plaintext reaches `HttpL4Stage`.
- [ ] Allowed SMTP plaintext reaches `SmtpL4Stage`.
- [ ] Blocked plaintext does not emit encrypted output.
- [ ] Bypass forwards original encrypted packets.
- [ ] No decrypted plaintext is converted into `PacketContext`.
- [ ] No decrypted plaintext is sent to `TunForwarder`.
- [ ] Production startup does not install transparent redirect for managed HTTPS.
- [ ] `cargo test -p ngfw` passes.
- [ ] Vagrant h2 HTTPS smoke passes.
- [ ] r1 logs show L4 TLS path.

This plan is complete only when every item above is true. Keeping the old `MitmProxy` redirect path as the active production HTTPS inspection path does not satisfy this plan.
