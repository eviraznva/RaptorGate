# Decrypted Flow Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace TLS plaintext inspection through synthetic `PacketContext` objects with a first-class `DecryptedFlowContext`, then preserve a clear path for TLS L4 decryption to feed plaintext HTTP into an HTTP L4 stage.

**Architecture:** Keep the normal `DataPipeline` for real packets only. Add a decrypted flow model and pipeline consumed by `InspectionRelay` through the existing `DecryptedTrafficInspector` boundary. Refactor policy evaluation to read explicit flow fields so both real packet policy and decrypted plaintext policy use the same rule evaluator without constructing fake packets. Treat this as phase one: the later target is a TCP L4 TLS decrypt stage that returns plaintext chunks to an HTTP L4 stage, without reinjecting decrypted bytes onto a virtual interface.

**Tech Stack:** Rust 2024, Tokio, tonic async traits, existing RaptorGate DPI/IPS/policy modules, existing TLS MITM runtime.

---

## File Structure

**Create**
- `crates/raptorgate/src/tls/decrypted_flow.rs`: `DecryptedFlowContext`, `DecryptedFlowStage`, `DecryptedFlowPipeline`, production decrypted DPI/IPS/policy stages, and `DecryptedFlowInspector`.

**Future L4 handoff files**
- `crates/raptorgate/src/tls/l4_decrypt.rs`: future `TlsL4DecryptStage`, session-local TLS state, and plaintext chunk output contract.
- `crates/raptorgate/src/l4/http.rs`: future HTTP L4 stage that consumes plaintext HTTP from plain TCP or TLS decryption.
- `crates/raptorgate/src/l4/factory.rs`: future TCP pipeline wiring for `TlsL4DecryptStage -> HttpL4Stage`.
- `crates/raptorgate/src/conntrack/session_manager.rs`: future async handoff if TLS decryption cannot run inside the current synchronous `L4Stage::on_bytes()` API.

**Modify**
- `crates/raptorgate/src/dpi/classifier.rs`: add payload-based flow inspection and keep packet inspection as a wrapper.
- `crates/raptorgate/src/policy/policy_evaluator.rs`: replace `SlicedPacket` dependency in `PolicyEvalContext` with explicit `PolicyFlowFields`.
- `crates/raptorgate/src/pipeline/wrappers.rs`: build `PolicyFlowFields` from real `PacketContext` before policy evaluation.
- `crates/raptorgate/src/tls/decrypted_chain.rs`: remove synthetic packet inspector or reduce this file to a compatibility re-export while tests move to `decrypted_flow.rs`.
- `crates/raptorgate/src/tls/inspection_relay.rs`: import `DecryptedTrafficInspector`, `InspectionDecision`, and `InspectionDisposition` from the new flow module.
- `crates/raptorgate/src/tls/mod.rs`: export `decrypted_flow` and stop exporting the synthetic inspector.
- `crates/raptorgate/src/main.rs`: construct `DecryptedFlowInspector` instead of `DecryptedChainInspector::with_identity(pipeline.clone(), ...)`.

**Do not modify**
- `crates/raptorgate/src/tls/transparent_redirect.rs`
- `crates/raptorgate/src/tls/upstream_connector.rs`
- `crates/raptorgate/src/tls/redirect_manager.rs`
- `crates/raptorgate/src/tls/cert_forger.rs`
- backend and protobuf files

---

## Task 1: Add Payload-Based DPI Flow Inspection

**Files:**
- Modify: `crates/raptorgate/src/dpi/classifier.rs`

- [ ] **Step 1: Add failing tests for packet-free DPI**

Add these tests to the existing `#[cfg(test)]` module in `crates/raptorgate/src/dpi/classifier.rs`:

```rust
#[test]
fn inspect_flow_payload_classifies_http_without_packet() {
    let classifier = DpiClassifier::new();
    let result = classifier.inspect_flow_payload(
        "192.168.20.10".parse().unwrap(),
        53120,
        "142.250.186.4".parse().unwrap(),
        443,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );

    match result {
        InspectResult::Done(ctx) => {
            assert_eq!(ctx.app_proto, Some(AppProto::Http));
            assert_eq!(ctx.http_host.as_deref(), Some("example.com"));
        }
        other => panic!("expected HTTP classification, got {other:?}"),
    }
}

#[test]
fn inspect_packet_still_uses_same_flow_buffering() {
    let classifier = DpiClassifier::new();
    let packet = build_tcp_packet(
        [192, 168, 20, 10],
        [142, 250, 186, 4],
        53120,
        443,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    let sliced = etherparse::SlicedPacket::from_ethernet(&packet).unwrap();

    match classifier.inspect_packet(&sliced) {
        InspectResult::Done(ctx) => assert_eq!(ctx.app_proto, Some(AppProto::Http)),
        other => panic!("expected HTTP classification, got {other:?}"),
    }
}
```

If the test module does not already have a packet helper, add this helper inside the test module:

```rust
fn build_tcp_packet(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(src, dst, 64)
        .tcp(src_port, dst_port, 0, 65_535);
    let mut raw = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut raw, payload).unwrap();
    raw
}
```

Run: `cargo test -p ngfw dpi::classifier::tests::inspect_flow_payload_classifies_http_without_packet`

Expected: FAIL because `inspect_flow_payload` is not defined.

- [ ] **Step 2: Implement payload-based DPI method**

In `impl DpiClassifier`, replace the body of `inspect_packet()` with a wrapper around a new method:

```rust
pub fn inspect_packet(&self, packet: &SlicedPacket) -> InspectResult {
    let Some((key, payload)) = Self::extract_flow(packet) else {
        return InspectResult::Skipped;
    };

    self.inspect_payload_for_key(key, payload)
}
```

Then add the public payload method and a private shared implementation to `DpiClassifier`:

```rust
pub fn inspect_flow_payload(
    &self,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> InspectResult {
    let key = FlowKey::new(src_ip, src_port, dst_ip, dst_port);
    self.inspect_payload_for_key(key, payload)
}

fn inspect_payload_for_key(&self, key: FlowKey, payload: &[u8]) -> InspectResult {
    if payload.is_empty() {
        return InspectResult::Skipped;
    }

    let mut entry = self.sessions.entry(key).or_insert_with(DpiSessionEntry::new);
    let session = entry.value_mut();

    session.append_payload(payload);

    if let Some(ref mut ctx) = session.result {
        if ctx.app_proto == Some(AppProto::Dns) {
            if let Some(parsed) = dns::parse_dns(payload) {
                if parsed.is_response {
                    ctx.dns_answer_count = parsed.answer_count;
                    ctx.dns_answer_types = parsed.answer_types;
                    ctx.dns_authority_count = parsed.authority_count;
                    ctx.dns_authority_types = parsed.authority_types;
                    ctx.dns_additional_count = parsed.additional_count;
                    ctx.dns_additional_types = parsed.additional_types;
                    ctx.dns_has_opt = parsed.has_opt;
                    ctx.dns_dnssec_ok = parsed.dnssec_ok;
                    ctx.dns_authentic_data = parsed.authentic_data;
                    ctx.dns_checking_disabled = parsed.checking_disabled;
                    ctx.dns_rcode = parsed.rcode;
                    ctx.dns_has_dnssec_records = parsed.has_dnssec_records;
                    ctx.dns_response_size = parsed.response_size;
                } else {
                    *ctx = dns::dns_to_dpi_context(&parsed);
                }
            }
        } else if ctx.app_proto == Some(AppProto::Http) {
            if let Some(parsed) = http::parse_http(&session.buffer) {
                http::merge_http_dpi_context(ctx, &parsed);
            }
        }
        return InspectResult::Done(ctx.clone());
    }

    if let Some(ctx) = Self::try_classify(&session.buffer) {
        session.result = Some(ctx.clone());
        return InspectResult::Done(ctx);
    }

    if session.limits_exceeded() {
        let ctx = DpiContext {
            app_proto: Some(AppProto::Unknown),
            ..Default::default()
        };
        session.result = Some(ctx.clone());
        return InspectResult::Done(ctx);
    }

    InspectResult::NeedMore
}
```

Run: `cargo test -p ngfw dpi::classifier`

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/raptorgate/src/dpi/classifier.rs
git commit -m "refactor(dpi): inspect flow payloads without packets"
```

---

## Task 2: Refactor Policy Evaluation to Explicit Flow Fields

**Files:**
- Modify: `crates/raptorgate/src/policy/policy_evaluator.rs`
- Modify: `crates/raptorgate/src/pipeline/wrappers.rs`

- [ ] **Step 1: Add policy evaluator tests for explicit fields**

In `crates/raptorgate/src/policy/policy_evaluator.rs`, add a test that does not build a packet:

```rust
#[test]
fn evaluates_src_dst_ports_from_policy_flow_fields() {
    let tree = RuleTree::new(
        MatchBuilder::with_arm(
            MatchKind::DstPort,
            Pattern::Equal(FieldValue::Port(Port::from(443))),
            ArmEnd::Verdict(Verdict::Drop),
        )
        .build()
        .unwrap(),
    );
    let evaluator = PolicyEvaluator::new(tree, Verdict::Allow);
    let arrival = default_arrival();
    let flow = PolicyFlowFields {
        src_ip: "192.168.20.10".parse().unwrap(),
        dst_ip: "142.250.186.4".parse().unwrap(),
        ip_ver: IpVer::V4,
        protocol: Protocol::Tcp,
        src_port: Some(Port::from(53120)),
        dst_port: Some(Port::from(443)),
    };

    let verdict = evaluator.evaluate(PolicyEvalContext {
        flow,
        arrival: &arrival,
        dns: None,
        dpi: None,
        identity: None,
    });

    assert_eq!(verdict, Verdict::Drop);
}
```

Run: `cargo test -p ngfw policy::policy_evaluator::tests::evaluates_src_dst_ports_from_policy_flow_fields`

Expected: FAIL because `PolicyFlowFields` and the new context shape do not exist.

- [ ] **Step 2: Add `PolicyFlowFields` and update context**

In `crates/raptorgate/src/policy/policy_evaluator.rs`, replace the packet field in `PolicyEvalContext`:

```rust
#[derive(Clone, Copy)]
pub struct PolicyFlowFields {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub ip_ver: IpVer,
    pub protocol: Protocol,
    pub src_port: Option<Port>,
    pub dst_port: Option<Port>,
}

#[derive(Clone, Copy)]
pub struct PolicyEvalContext<'a> {
    pub flow: PolicyFlowFields,
    pub arrival: &'a ArrivalInfo,
    pub dns: Option<&'a DnsEvalContext>,
    pub dpi: Option<&'a DpiContext>,
    pub identity: Option<&'a IdentityContext>,
}
```

Update `PolicyEngine::evaluate()` in `crates/raptorgate/src/policy/engine.rs` to accept `PolicyEvalContext<'_>` instead of `PolicyEvalContext<'_, '_>`.

Update `PolicyEvaluator::evaluate()`, `evaluate_if_matches()`, `matches_kind()`, and `extract()` signatures to use `PolicyEvalContext<'_>`.

Replace packet-dependent extraction branches with explicit field access:

```rust
MatchKind::SrcIp => Some(FieldValue::Ip(ctx.flow.src_ip.into())),
MatchKind::DstIp => Some(FieldValue::Ip(ctx.flow.dst_ip.into())),
MatchKind::IpVer => Some(FieldValue::IpVer(ctx.flow.ip_ver)),
MatchKind::Protocol => Some(FieldValue::Protocol(ctx.flow.protocol)),
MatchKind::SrcPort => ctx.flow.src_port.map(FieldValue::Port),
MatchKind::DstPort => ctx.flow.dst_port.map(FieldValue::Port),
```

Run: `cargo test -p ngfw policy::policy_evaluator`

Expected: packet-path callers still fail to compile because they still pass `packet: ...`.

- [ ] **Step 3: Build policy flow fields from real packets**

In `crates/raptorgate/src/pipeline/wrappers.rs`, add this helper near `packet_log_fields()`:

```rust
fn policy_flow_fields_from_packet(ctx: &PacketContext) -> Option<PolicyFlowFields> {
    let sliced = ctx.borrow_sliced_packet();
    let (src_ip, dst_ip, ip_ver) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let h = ipv4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                crate::rule_tree::IpVer::V4,
            )
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let h = ipv6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                crate::rule_tree::IpVer::V6,
            )
        }
        _ => return None,
    };

    let (protocol, src_port, dst_port) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            crate::rule_tree::Protocol::Tcp,
            Some(crate::rule_tree::Port::from(tcp.source_port())),
            Some(crate::rule_tree::Port::from(tcp.destination_port())),
        ),
        Some(TransportSlice::Udp(udp)) => (
            crate::rule_tree::Protocol::Udp,
            Some(crate::rule_tree::Port::from(udp.source_port())),
            Some(crate::rule_tree::Port::from(udp.destination_port())),
        ),
        Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => (
            crate::rule_tree::Protocol::Icmp,
            None,
            None,
        ),
        _ => return None,
    };

    Some(PolicyFlowFields {
        src_ip,
        dst_ip,
        ip_ver,
        protocol,
        src_port,
        dst_port,
    })
}
```

Import `PolicyFlowFields` at the top of `wrappers.rs` with the existing policy evaluator imports.

In `PolicyEvalStage::process()`, before calling `policy_engine.evaluate()`, build:

```rust
let Some(flow) = policy_flow_fields_from_packet(ctx) else {
    return StageOutcome::Continue;
};
```

Then call:

```rust
let verdict = self.policy_engine.evaluate(pair_id, PolicyEvalContext {
    flow,
    arrival: &arrival,
    dns: dns_ctx.as_ref(),
    dpi: ctx.borrow_dpi_ctx().as_ref(),
    identity: ctx.borrow_identity_ctx().as_ref(),
});
```

Run: `cargo test -p ngfw policy pipeline::wrappers`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/raptorgate/src/policy/policy_evaluator.rs crates/raptorgate/src/policy/engine.rs crates/raptorgate/src/pipeline/wrappers.rs
git commit -m "refactor(policy): evaluate explicit flow fields"
```

---

## Task 3: Add Decrypted Flow Context and Pipeline Types

**Files:**
- Create: `crates/raptorgate/src/tls/decrypted_flow.rs`
- Modify: `crates/raptorgate/src/tls/mod.rs`

- [ ] **Step 1: Add failing context tests**

Create `crates/raptorgate/src/tls/decrypted_flow.rs` with only imports and these tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use uuid::Uuid;

    fn meta() -> SessionMeta {
        SessionMeta {
            session_id: Uuid::now_v7(),
            peer: "192.168.20.10:53120".parse().unwrap(),
            server: "142.250.186.4:443".parse().unwrap(),
            original_dst: "142.250.186.4:443".parse().unwrap(),
            sni: Some("www.google.com".to_string()),
            alpn: Some(b"h2".to_vec()),
            client_side_interface: Some("eth1".to_string()),
            server_side_interface: Some("eth0".to_string()),
            mode: InspectionMode::Outbound,
        }
    }

    #[test]
    fn context_uses_client_to_server_endpoints_and_interface() {
        let ctx = DecryptedFlowContext::new(
            b"GET / HTTP/1.1\r\n\r\n",
            DpiContext::default(),
            Direction::ClientToServer,
            &meta(),
            SystemTime::UNIX_EPOCH,
            None,
        );

        assert_eq!(ctx.src, "192.168.20.10:53120".parse::<SocketAddr>().unwrap());
        assert_eq!(ctx.dst, "142.250.186.4:443".parse::<SocketAddr>().unwrap());
        assert_eq!(ctx.source_interface.as_deref(), Some("eth1"));
        assert!(ctx.dpi.decrypted);
        assert_eq!(ctx.dpi.src_port, Some(53120));
        assert_eq!(ctx.dpi.dst_port, Some(443));
    }

    #[test]
    fn context_uses_server_to_client_endpoints_and_interface() {
        let ctx = DecryptedFlowContext::new(
            b"HTTP/1.1 200 OK\r\n\r\n",
            DpiContext::default(),
            Direction::ServerToClient,
            &meta(),
            SystemTime::UNIX_EPOCH,
            None,
        );

        assert_eq!(ctx.src, "142.250.186.4:443".parse::<SocketAddr>().unwrap());
        assert_eq!(ctx.dst, "192.168.20.10:53120".parse::<SocketAddr>().unwrap());
        assert_eq!(ctx.source_interface.as_deref(), Some("eth0"));
        assert!(ctx.dpi.decrypted);
        assert_eq!(ctx.dpi.src_port, Some(443));
        assert_eq!(ctx.dpi.dst_port, Some(53120));
    }
}
```

Run: `cargo test -p ngfw tls::decrypted_flow::tests::context_uses_client_to_server_endpoints_and_interface`

Expected: FAIL because the module and types are incomplete.

- [ ] **Step 2: Implement core flow types**

In `crates/raptorgate/src/tls/decrypted_flow.rs`, add:

```rust
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use tonic::async_trait;

use crate::data_plane::ips::ips::{Ips, IpsSignatureMatch, IpsVerdict};
use crate::dpi::{AppProto, DpiClassifier, DpiContext, InspectResult};
use crate::identity::{resolve_identity, IdentityContext, IdentitySessionStore};
use crate::policy::engine::PolicyEngine;
use crate::policy::policy_evaluator::{PolicyEvalContext, PolicyFlowFields};
use crate::rule_tree::{ArrivalInfo, IpVer, Port, Protocol, Verdict};
use crate::tls::inspection_relay::{Direction, InspectionMode, SessionMeta};
use crate::zones::resolver::ZoneResolver;
```

Move or recreate the existing inspection boundary types:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionDisposition {
    Forward,
    Drop,
}

pub struct InspectionDecision {
    pub disposition: InspectionDisposition,
    pub ctx: DpiContext,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait DecryptedTrafficInspector: Send + Sync {
    async fn inspect(
        &self,
        payload: &[u8],
        seed_ctx: &DpiContext,
        direction: Direction,
        meta: &SessionMeta,
    ) -> InspectionDecision;

    fn close_session(&self, _meta: &SessionMeta) {}
}

pub struct NoopDecryptedInspector;

#[async_trait]
impl DecryptedTrafficInspector for NoopDecryptedInspector {
    async fn inspect(
        &self,
        payload: &[u8],
        seed_ctx: &DpiContext,
        _direction: Direction,
        _meta: &SessionMeta,
    ) -> InspectionDecision {
        InspectionDecision {
            disposition: InspectionDisposition::Forward,
            ctx: seed_ctx.clone(),
            payload: payload.to_vec(),
        }
    }
}
```

Add context and stage types:

```rust
pub struct DecryptedFlowContext {
    pub payload: Vec<u8>,
    pub direction: Direction,
    pub session: SessionMeta,
    pub arrival_time: SystemTime,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub source_interface: Option<String>,
    pub identity: Option<IdentityContext>,
    pub dpi: DpiContext,
    pub warnings: Vec<String>,
}

impl DecryptedFlowContext {
    pub fn new(
        payload: &[u8],
        mut seed_ctx: DpiContext,
        direction: Direction,
        meta: &SessionMeta,
        arrival_time: SystemTime,
        identity: Option<IdentityContext>,
    ) -> Self {
        let (src, dst) = endpoints_for_direction(meta, direction);
        seed_ctx.decrypted = true;
        seed_ctx.src_port = Some(src.port());
        seed_ctx.dst_port = Some(dst.port());

        Self {
            payload: payload.to_vec(),
            direction,
            session: meta.clone(),
            arrival_time,
            src,
            dst,
            source_interface: meta.source_interface_for_direction(direction).map(ToOwned::to_owned),
            identity,
            dpi: seed_ctx,
            warnings: Vec::new(),
        }
    }

    pub fn policy_flow_fields(&self) -> PolicyFlowFields {
        let ip_ver = match (self.src.ip(), self.dst.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => IpVer::V4,
            (IpAddr::V6(_), IpAddr::V6(_)) => IpVer::V6,
            _ => IpVer::V4,
        };

        PolicyFlowFields {
            src_ip: self.src.ip(),
            dst_ip: self.dst.ip(),
            ip_ver,
            protocol: Protocol::Tcp,
            src_port: Some(Port::from(self.src.port())),
            dst_port: Some(Port::from(self.dst.port())),
        }
    }
}

fn endpoints_for_direction(meta: &SessionMeta, direction: Direction) -> (SocketAddr, SocketAddr) {
    match direction {
        Direction::ClientToServer => (meta.peer, meta.server),
        Direction::ServerToClient => (meta.server, meta.peer),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptedFlowOutcome {
    Continue,
    Drop { reason: String },
}

#[async_trait]
pub trait DecryptedFlowStage: Send + Sync {
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome;
}

#[derive(Clone)]
pub struct DecryptedFlowPipeline {
    stages: Arc<Vec<Arc<dyn DecryptedFlowStage>>>,
}

impl DecryptedFlowPipeline {
    pub fn new(stages: Vec<Arc<dyn DecryptedFlowStage>>) -> Self {
        Self {
            stages: Arc::new(stages),
        }
    }

    pub async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome {
        for stage in self.stages.iter() {
            match stage.process(ctx).await {
                DecryptedFlowOutcome::Continue => {}
                drop @ DecryptedFlowOutcome::Drop { .. } => return drop,
            }
        }
        DecryptedFlowOutcome::Continue
    }
}
```

Export the module in `crates/raptorgate/src/tls/mod.rs`:

```rust
pub mod decrypted_flow;
pub use decrypted_flow::{
    DecryptedFlowContext, DecryptedFlowOutcome, DecryptedFlowPipeline,
    DecryptedFlowStage, DecryptedTrafficInspector, InspectionDecision,
    InspectionDisposition, NoopDecryptedInspector,
};
```

Run: `cargo test -p ngfw tls::decrypted_flow::tests`

Expected: PASS for the context tests.

- [ ] **Step 3: Commit**

```bash
git add crates/raptorgate/src/tls/decrypted_flow.rs crates/raptorgate/src/tls/mod.rs
git commit -m "feat(tls): add decrypted flow context"
```

---

## Task 4: Implement Decrypted DPI and IPS Stages

**Files:**
- Modify: `crates/raptorgate/src/tls/decrypted_flow.rs`

- [ ] **Step 1: Add failing stage tests**

Add tests in `crates/raptorgate/src/tls/decrypted_flow.rs`:

```rust
#[tokio::test]
async fn decrypted_dpi_stage_classifies_http_plaintext() {
    let stage = DecryptedDpiStage {
        classifier: Arc::new(DpiClassifier::new()),
    };
    let mut ctx = DecryptedFlowContext::new(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        DpiContext::default(),
        Direction::ClientToServer,
        &meta(),
        SystemTime::UNIX_EPOCH,
        None,
    );

    assert_eq!(stage.process(&mut ctx).await, DecryptedFlowOutcome::Continue);
    assert_eq!(ctx.dpi.app_proto, Some(AppProto::Http));
    assert_eq!(ctx.dpi.http_host.as_deref(), Some("example.com"));
    assert!(ctx.dpi.decrypted);
}

#[tokio::test]
async fn decrypted_ips_stage_blocks_matching_plaintext() {
    let ips = Ips::new(test_ips_config_blocking_literal("UNION SELECT")).unwrap();
    let stage = DecryptedIpsStage { inspection: ips };
    let mut ctx = DecryptedFlowContext::new(
        b"GET /?q=UNION SELECT HTTP/1.1\r\nHost: x\r\n\r\n",
        DpiContext {
            app_proto: Some(AppProto::Http),
            ..Default::default()
        },
        Direction::ClientToServer,
        &meta(),
        SystemTime::UNIX_EPOCH,
        None,
    );

    match stage.process(&mut ctx).await {
        DecryptedFlowOutcome::Drop { reason } => assert!(reason.contains("UNION SELECT")),
        other => panic!("expected IPS drop, got {other:?}"),
    }
    assert!(ctx.dpi.ips_match.as_ref().is_some_and(|m| m.blocked));
}
```

Add this local helper in the test module:

```rust
fn test_ips_config_blocking_literal(pattern: &str) -> crate::data_plane::ips::config::IpsConfig {
    use crate::data_plane::ips::config::{
        IpsAction, IpsAppProtocol, IpsConfig, IpsDetectionConfig, IpsGeneralConfig,
        IpsMatchType, IpsPatternEncoding, IpsSeverity, IpsSignatureConfig,
    };

    IpsConfig {
        general: IpsGeneralConfig { enabled: true },
        detection: IpsDetectionConfig {
            enabled: true,
            max_payload_bytes: 512,
            max_matches_per_packet: 4,
        },
        signatures: vec![IpsSignatureConfig {
            id: "tls-http-sqli".into(),
            name: pattern.into(),
            enabled: true,
            category: "sqli".into(),
            pattern: pattern.into(),
            match_type: IpsMatchType::Literal,
            pattern_encoding: IpsPatternEncoding::Text,
            case_insensitive: true,
            severity: IpsSeverity::High,
            action: IpsAction::Block,
            app_protocols: vec![IpsAppProtocol::Http],
            src_ports: vec![],
            dst_ports: vec![443],
        }],
    }
}
```

Run: `cargo test -p ngfw tls::decrypted_flow::tests::decrypted_dpi_stage_classifies_http_plaintext`

Expected: FAIL because stage types are missing.

- [ ] **Step 2: Implement `DecryptedDpiStage`**

Add this stage:

```rust
#[derive(Clone)]
pub struct DecryptedDpiStage {
    pub classifier: Arc<DpiClassifier>,
}

#[async_trait]
impl DecryptedFlowStage for DecryptedDpiStage {
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome {
        match self.classifier.inspect_flow_payload(
            ctx.src.ip(),
            ctx.src.port(),
            ctx.dst.ip(),
            ctx.dst.port(),
            &ctx.payload,
        ) {
            InspectResult::Done(mut dpi) => {
                merge_decrypted_dpi(&ctx.dpi, &mut dpi);
                ctx.dpi = dpi;
            }
            InspectResult::NeedMore | InspectResult::Skipped => {
                ctx.dpi.decrypted = true;
                ctx.dpi.src_port = ctx.dpi.src_port.or(Some(ctx.src.port()));
                ctx.dpi.dst_port = ctx.dpi.dst_port.or(Some(ctx.dst.port()));
            }
        }
        DecryptedFlowOutcome::Continue
    }
}

fn merge_decrypted_dpi(existing: &DpiContext, next: &mut DpiContext) {
    next.decrypted = true;
    next.src_port = next.src_port.or(existing.src_port);
    next.dst_port = next.dst_port.or(existing.dst_port);
    next.ips_match = existing.ips_match.clone();

    if next.app_proto.is_none() {
        next.app_proto = existing.app_proto;
    }
}
```

Run: `cargo test -p ngfw tls::decrypted_flow::tests::decrypted_dpi_stage_classifies_http_plaintext`

Expected: PASS.

- [ ] **Step 3: Implement `DecryptedIpsStage`**

Add this stage:

```rust
#[derive(Clone)]
pub struct DecryptedIpsStage {
    pub inspection: Arc<Ips>,
}

#[async_trait]
impl DecryptedFlowStage for DecryptedIpsStage {
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome {
        ctx.dpi.ips_match = None;

        match self.inspection.inspect_decrypted(
            &ctx.payload,
            ctx.dpi.app_proto,
            ctx.src.port(),
            ctx.dst.port(),
        ) {
            IpsVerdict::Allow => DecryptedFlowOutcome::Continue,
            IpsVerdict::Alert(matches) => {
                if let Some(first) = matches.first() {
                    ctx.dpi.ips_match = Some(crate::dpi::IpsMatch {
                        signature_name: first.name.clone(),
                        severity: first.severity.as_str().to_string(),
                        blocked: false,
                    });
                }
                for matched in matches {
                    ctx.warnings.push(matched.message());
                }
                DecryptedFlowOutcome::Continue
            }
            IpsVerdict::Block(matched) => {
                let reason = matched.message();
                ctx.dpi.ips_match = Some(crate::dpi::IpsMatch {
                    signature_name: matched.name.clone(),
                    severity: matched.severity.as_str().to_string(),
                    blocked: true,
                });
                ctx.warnings.push(reason.clone());
                DecryptedFlowOutcome::Drop { reason }
            }
        }
    }
}
```

Update the `pub use decrypted_flow::{ ... }` list in `crates/raptorgate/src/tls/mod.rs` to include:

```rust
DecryptedDpiStage, DecryptedIpsStage,
```

Update the `pub use decrypted_flow::{ ... }` list in `crates/raptorgate/src/tls/mod.rs` to include:

```rust
DecryptedPolicyStage,
```

Run: `cargo test -p ngfw tls::decrypted_flow`

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/raptorgate/src/tls/decrypted_flow.rs crates/raptorgate/src/tls/mod.rs
git commit -m "feat(tls): inspect decrypted flow dpi and ips"
```

---

## Task 5: Implement Decrypted Policy Stage

**Files:**
- Modify: `crates/raptorgate/src/tls/decrypted_flow.rs`

- [ ] **Step 1: Add failing policy stage tests**

Add tests to `crates/raptorgate/src/tls/decrypted_flow.rs`:

```rust
#[tokio::test]
async fn decrypted_policy_stage_drops_policy_drop_verdict() {
    let policy_engine = Arc::new(policy_engine_for_dst_port(Verdict::Drop, 443));
    let zone_resolver = Arc::new(FixedZoneResolver::new("00000000-0000-0000-0000-000000000123"));
    let stage = DecryptedPolicyStage {
        policy_engine,
        zone_resolver,
    };
    let mut ctx = DecryptedFlowContext::new(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        DpiContext { app_proto: Some(AppProto::Http), ..Default::default() },
        Direction::ClientToServer,
        &meta(),
        SystemTime::UNIX_EPOCH,
        None,
    );

    assert!(matches!(
        stage.process(&mut ctx).await,
        DecryptedFlowOutcome::Drop { .. }
    ));
}

#[tokio::test]
async fn decrypted_policy_stage_allows_policy_allow_verdict() {
    let policy_engine = Arc::new(policy_engine_for_dst_port(Verdict::Allow, 443));
    let zone_resolver = Arc::new(FixedZoneResolver::new("00000000-0000-0000-0000-000000000123"));
    let stage = DecryptedPolicyStage {
        policy_engine,
        zone_resolver,
    };
    let mut ctx = DecryptedFlowContext::new(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        DpiContext { app_proto: Some(AppProto::Http), ..Default::default() },
        Direction::ClientToServer,
        &meta(),
        SystemTime::UNIX_EPOCH,
        None,
    );

    assert_eq!(stage.process(&mut ctx).await, DecryptedFlowOutcome::Continue);
}
```

Add these test helpers:

```rust
#[derive(Clone)]
struct FixedZoneResolver {
    pair_id: crate::zones::ZonePairId,
}

impl FixedZoneResolver {
    fn new(id: &str) -> Self {
        Self {
            pair_id: crate::zones::ZonePairId::from(uuid::Uuid::parse_str(id).unwrap()),
        }
    }
}

impl crate::zones::resolver::ZoneResolver for FixedZoneResolver {
    fn resolve(&self, _iface: &str, _dst_ip: IpAddr) -> Option<crate::zones::ResolvedZonePair> {
        Some(crate::zones::ResolvedZonePair {
            id: self.pair_id.clone(),
            default_policy: crate::zones::DefaultPolicy::Allow,
        })
    }

    fn resolve_bidirectional(
        &self,
        _src_ip: IpAddr,
        _dst_ip: IpAddr,
    ) -> crate::zones::DirectionalZonePairs {
        crate::zones::DirectionalZonePairs {
            forward: Some(crate::zones::ResolvedZonePair {
                id: self.pair_id.clone(),
                default_policy: crate::zones::DefaultPolicy::Allow,
            }),
            reverse: Some(crate::zones::ResolvedZonePair {
                id: self.pair_id.clone(),
                default_policy: crate::zones::DefaultPolicy::Allow,
            }),
        }
    }
}

fn policy_engine_for_dst_port(verdict: Verdict, dst_port: u16) -> PolicyEngine {
    use std::collections::HashMap;

    let zone_pair_id = crate::zones::ZonePairId::from(
        uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000123").unwrap(),
    );
    let policy = crate::policy::Policy {
        name: "decrypted-flow-policy".into(),
        zone_pair_id: zone_pair_id.clone(),
        priority: 1,
        rule_tree: crate::rule_tree::RuleTree::new(
            crate::rule_tree::MatchBuilder::with_arm(
                crate::rule_tree::MatchKind::DstPort,
                crate::rule_tree::Pattern::Equal(crate::rule_tree::FieldValue::Port(
                    crate::rule_tree::Port::from(dst_port),
                )),
                crate::rule_tree::ArmEnd::Verdict(verdict),
            )
            .build()
            .unwrap(),
        ),
        smtp_policy: crate::policy::SmtpPolicy::default(),
    };
    let zone_pair = crate::zones::ZonePair {
        src_zone_id: uuid::Uuid::from_u128(1).into(),
        dst_zone_id: uuid::Uuid::from_u128(2).into(),
        default_policy: crate::zones::DefaultPolicy::Allow,
    };

    let mut policies = HashMap::new();
    policies.insert(crate::policy::PolicyId::from(uuid::Uuid::from_u128(3)), policy);

    let mut zone_pairs = HashMap::new();
    zone_pairs.insert(zone_pair_id, zone_pair);

    PolicyEngine::from_policies(&policies, &zone_pairs).unwrap()
}
```

Run: `cargo test -p ngfw tls::decrypted_flow::tests::decrypted_policy_stage_drops_policy_drop_verdict`

Expected: FAIL because `DecryptedPolicyStage` is missing.

- [ ] **Step 2: Implement policy stage**

Add:

```rust
#[derive(Clone)]
pub struct DecryptedPolicyStage<ZR>
where
    ZR: ZoneResolver,
{
    pub policy_engine: Arc<PolicyEngine>,
    pub zone_resolver: Arc<ZR>,
}

#[async_trait]
impl<ZR> DecryptedFlowStage for DecryptedPolicyStage<ZR>
where
    ZR: ZoneResolver + Send + Sync + 'static,
{
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome {
        let Some(source_interface) = ctx.source_interface.as_deref() else {
            tracing::warn!(
                event = "tls.decrypted.policy.source_interface.missing",
                session_id = %ctx.session.session_id,
                peer = %ctx.session.peer,
                server = %ctx.session.server,
                direction = ?ctx.direction,
                "decrypted policy source interface missing, allowing"
            );
            return DecryptedFlowOutcome::Continue;
        };

        let pair = self.zone_resolver.resolve(source_interface, ctx.dst.ip());
        let Some(pair) = pair else {
            tracing::warn!(
                event = "policy.zone_pair.missing",
                iface = %source_interface,
                dst_ip = %ctx.dst.ip(),
                "no matching zone pair for decrypted flow, allowing"
            );
            return DecryptedFlowOutcome::Continue;
        };

        let arrival = ArrivalInfo::from_time(&ctx.arrival_time);
        let verdict = self.policy_engine.evaluate(&pair.id, PolicyEvalContext {
            flow: ctx.policy_flow_fields(),
            arrival: &arrival,
            dns: None,
            dpi: Some(&ctx.dpi),
            identity: ctx.identity.as_ref(),
        });

        match verdict {
            Some(Verdict::Allow) | None => DecryptedFlowOutcome::Continue,
            Some(Verdict::Drop) => {
                let reason = "decrypted policy returned drop verdict".to_string();
                tracing::warn!(
                    event = "tls.decrypted.policy.dropped",
                    session_id = %ctx.session.session_id,
                    peer = %ctx.session.peer,
                    server = %ctx.session.server,
                    direction = ?ctx.direction,
                    "decrypted flow dropped by policy"
                );
                DecryptedFlowOutcome::Drop { reason }
            }
            Some(Verdict::AllowWarn(message)) => {
                ctx.warnings.push(message);
                DecryptedFlowOutcome::Continue
            }
        }
    }
}
```

If `ArrivalInfo::from_time()` expects `SystemTime` by value rather than reference, pass `ctx.arrival_time`.

Run: `cargo test -p ngfw tls::decrypted_flow`

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/raptorgate/src/tls/decrypted_flow.rs crates/raptorgate/src/tls/mod.rs
git commit -m "feat(tls): apply policy to decrypted flows"
```

---

## Task 6: Replace Synthetic Inspector with `DecryptedFlowInspector`

**Files:**
- Modify: `crates/raptorgate/src/tls/decrypted_flow.rs`
- Modify: `crates/raptorgate/src/tls/decrypted_chain.rs`
- Modify: `crates/raptorgate/src/tls/inspection_relay.rs`
- Modify: `crates/raptorgate/src/tls/mod.rs`

- [ ] **Step 1: Add failing inspector regression test**

Add to `crates/raptorgate/src/tls/decrypted_flow.rs`:

```rust
#[tokio::test]
async fn flow_inspector_forwards_clean_plaintext_without_execution_sender() {
    let pipeline = DecryptedFlowPipeline::new(vec![
        Arc::new(DecryptedDpiStage { classifier: Arc::new(DpiClassifier::new()) }),
    ]);
    let inspector = DecryptedFlowInspector::new(
        pipeline,
        Arc::new(DpiClassifier::new()),
        IdentitySessionStore::new_shared(),
    );

    let decision = inspector.inspect(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        &DpiContext::default(),
        Direction::ClientToServer,
        &meta(),
    ).await;

    assert_eq!(decision.disposition, InspectionDisposition::Forward);
    assert_eq!(decision.payload, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert!(decision.ctx.decrypted);
}
```

Run: `cargo test -p ngfw tls::decrypted_flow::tests::flow_inspector_forwards_clean_plaintext_without_execution_sender`

Expected: FAIL because `DecryptedFlowInspector` is missing.

- [ ] **Step 2: Implement `DecryptedFlowInspector`**

Add:

```rust
pub struct DecryptedFlowInspector {
    pipeline: DecryptedFlowPipeline,
    dpi_classifier: Arc<DpiClassifier>,
    identity_sessions: Arc<IdentitySessionStore>,
}

impl DecryptedFlowInspector {
    pub fn new(
        pipeline: DecryptedFlowPipeline,
        dpi_classifier: Arc<DpiClassifier>,
        identity_sessions: Arc<IdentitySessionStore>,
    ) -> Self {
        Self {
            pipeline,
            dpi_classifier,
            identity_sessions,
        }
    }
}

#[async_trait]
impl DecryptedTrafficInspector for DecryptedFlowInspector {
    async fn inspect(
        &self,
        payload: &[u8],
        seed_ctx: &DpiContext,
        direction: Direction,
        meta: &SessionMeta,
    ) -> InspectionDecision {
        let arrival_time = SystemTime::now();
        let identity = resolve_identity(&self.identity_sessions, meta.peer.ip(), arrival_time);
        let mut ctx = DecryptedFlowContext::new(
            payload,
            seed_ctx.clone(),
            direction,
            meta,
            arrival_time,
            Some(identity),
        );

        tracing::trace!(
            event = "tls.decrypted.flow.inspect.started",
            session_id = %meta.session_id,
            peer = %meta.peer,
            server = %meta.server,
            direction = ?direction,
            "decrypted flow inspection started"
        );

        let outcome = self.pipeline.process(&mut ctx).await;
        let disposition = match outcome {
            DecryptedFlowOutcome::Continue => InspectionDisposition::Forward,
            DecryptedFlowOutcome::Drop { reason } => {
                tracing::warn!(
                    event = "tls.decrypted.flow.inspect.completed",
                    session_id = %meta.session_id,
                    peer = %meta.peer,
                    server = %meta.server,
                    direction = ?direction,
                    reason = %reason,
                    "decrypted flow inspection dropped payload"
                );
                InspectionDisposition::Drop
            }
        };

        InspectionDecision {
            disposition,
            ctx: ctx.dpi,
            payload: ctx.payload,
        }
    }

    fn close_session(&self, meta: &SessionMeta) {
        self.dpi_classifier.remove_session(
            meta.peer.ip(),
            meta.peer.port(),
            meta.server.ip(),
            meta.server.port(),
        );
        self.dpi_classifier.remove_session(
            meta.server.ip(),
            meta.server.port(),
            meta.peer.ip(),
            meta.peer.port(),
        );
    }
}
```

Run: `cargo test -p ngfw tls::decrypted_flow::tests::flow_inspector_forwards_clean_plaintext_without_execution_sender`

Expected: PASS.

- [ ] **Step 3: Move imports away from `decrypted_chain`**

In `crates/raptorgate/src/tls/inspection_relay.rs`, change:

```rust
use crate::tls::decrypted_chain::{
    DecryptedTrafficInspector, InspectionDisposition,
};
```

to:

```rust
use crate::tls::decrypted_flow::{
    DecryptedTrafficInspector, InspectionDisposition,
};
```

Update test references from `crate::tls::decrypted_chain::NoopDecryptedInspector` to `crate::tls::decrypted_flow::NoopDecryptedInspector`.

In `crates/raptorgate/src/tls/mod.rs`, export the new module:

```rust
pub mod decrypted_flow;
pub use decrypted_flow::{
    DecryptedDpiStage, DecryptedFlowContext, DecryptedFlowInspector,
    DecryptedFlowOutcome, DecryptedFlowPipeline, DecryptedFlowStage,
    DecryptedIpsStage, DecryptedPolicyStage, DecryptedTrafficInspector,
    InspectionDecision, InspectionDisposition, NoopDecryptedInspector,
};
```

Remove `pub use decrypted_chain::DecryptedChainInspector;`.

Run: `cargo test -p ngfw tls::inspection_relay`

Expected: PASS.

- [ ] **Step 4: Remove synthetic packet implementation**

Delete or empty `crates/raptorgate/src/tls/decrypted_chain.rs`. The preferred end state is to remove the module from `tls/mod.rs`.

If keeping the file temporarily avoids a large module churn, replace its contents with:

```rust
pub use crate::tls::decrypted_flow::*;
```

Do not keep `build_packet_context()`, `build_tcp_packet()`, or any `PacketBuilder::ethernet2()` code in TLS decrypted inspection.

Run: `rg -n "build_packet_context|failed to synthesize decrypted packet|Przepuszcza odszyfrowany payload|PacketBuilder::ethernet2" crates/raptorgate/src/tls`

Expected: no matches for the old synthetic TLS decrypted path.

- [ ] **Step 5: Commit**

```bash
git add crates/raptorgate/src/tls/decrypted_flow.rs crates/raptorgate/src/tls/decrypted_chain.rs crates/raptorgate/src/tls/inspection_relay.rs crates/raptorgate/src/tls/mod.rs
git commit -m "refactor(tls): replace synthetic decrypted packets"
```

---

## Task 7: Wire Decrypted Flow Pipeline in `main.rs`

**Files:**
- Modify: `crates/raptorgate/src/main.rs`

- [ ] **Step 1: Replace TLS inspector construction**

In `crates/raptorgate/src/main.rs`, replace the `DecryptedChainInspector::with_identity(...)` construction with explicit decrypted flow pipeline construction:

```rust
let decrypted_flow_pipeline = DecryptedFlowPipeline::new(vec![
    Arc::new(DecryptedDpiStage {
        classifier: Arc::clone(&dpi_classifier),
    }),
    Arc::new(DecryptedIpsStage {
        inspection: Arc::clone(&ips),
    }),
    Arc::new(DecryptedPolicyStage {
        policy_engine: Arc::clone(&policy_engine),
        zone_resolver: Arc::clone(&zone_resolver),
    }),
]);

let decrypted_inspector = Arc::new(DecryptedFlowInspector::new(
    decrypted_flow_pipeline,
    Arc::clone(&dpi_classifier),
    Arc::clone(&identity_sessions),
));
```

Then pass:

```rust
decrypted_inspector,
```

into `MitmProxyConfig`.

Update imports at the top of `main.rs` from `DecryptedChainInspector` to:

```rust
DecryptedDpiStage, DecryptedFlowInspector, DecryptedFlowPipeline, DecryptedIpsStage,
DecryptedPolicyStage,
```

Run: `cargo check -p ngfw`

Expected: compile errors identify missing exports or generic bounds. Fix imports or bounds in the smallest place where the compiler points.

- [ ] **Step 2: Prove no `ExecutionStage` is reachable from TLS plaintext wiring**

Add a unit test in `crates/raptorgate/src/tls/decrypted_flow.rs`:

```rust
#[tokio::test]
async fn decrypted_flow_pipeline_has_no_execution_sender_boundary() {
    let pipeline = DecryptedFlowPipeline::new(vec![]);
    let inspector = DecryptedFlowInspector::new(
        pipeline,
        Arc::new(DpiClassifier::new()),
        IdentitySessionStore::new_shared(),
    );
    let decision = inspector.inspect(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        &DpiContext::default(),
        Direction::ClientToServer,
        &meta(),
    ).await;

    assert_eq!(decision.disposition, InspectionDisposition::Forward);
}
```

This test must compile without importing `crate::pipeline::ExecutionSender`, `ExecutionItem`, or `Stage`.

Run: `cargo test -p ngfw tls::decrypted_flow::tests::decrypted_flow_pipeline_has_no_execution_sender_boundary`

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/raptorgate/src/main.rs crates/raptorgate/src/tls/decrypted_flow.rs
git commit -m "refactor(tls): wire decrypted flow pipeline"
```

---

## Task 8: Document and Guard the L4 TLS-to-HTTP Handoff Target

**Files:**
- Modify: `docs/superpowers/specs/2026-05-16-decrypted-flow-context-design.md`
- Modify: `docs/superpowers/plans/2026-05-16-decrypted-flow-context.md`

- [ ] **Step 1: Confirm the target flow is explicit in the spec**

Ensure the spec contains this target architecture:

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

Expected: the spec states that decrypted HTTPS bytes become plaintext chunks for `HttpL4Stage`, not packets for TUN or `DataPipeline`.

- [ ] **Step 2: Record the future L4 plaintext chunk contract**

Ensure the spec defines this future contract:

```rust
pub struct L4PlaintextChunk {
    pub payload: Vec<u8>,
    pub direction: Direction,
    pub app_proto: AppProto,
    pub dpi: DpiContext,
}
```

Expected: the spec states that `TlsL4DecryptStage` returns `L4PlaintextChunk` values and that `HttpL4Stage` consumes those chunks.

- [ ] **Step 3: Record the synchronous L4 API constraint**

The current `L4Stage::on_bytes()` API is synchronous:

```rust
fn on_bytes(
    &mut self,
    ctx: &mut Self::Ctx,
    packet_id: PacketId,
    dir: Direction,
    tcp_payload_start_seq: u32,
    payload: &[u8],
) -> L4Outcome;
```

Expected: the spec or follow-up implementation notes state that full TLS MITM cannot perform network handshakes directly inside this synchronous method. The later implementation must either add an async L4 boundary or use a session-local TLS worker/channel owned by the L4 session task.

- [ ] **Step 4: Add future test names to the plan**

Add these test requirements before implementing the L4 handoff:

```text
tls::l4_decrypt::tests::tls_l4_stage_emits_plaintext_chunks_without_packet_context
l4::http::tests::http_l4_stage_receives_decrypted_request_from_tls_stage
l4::http::tests::plain_http_and_decrypted_https_use_same_http_stage
```

Expected: each test name describes a packet-free handoff from TLS plaintext to HTTP L4 state.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-05-16-decrypted-flow-context-design.md docs/superpowers/plans/2026-05-16-decrypted-flow-context.md
git commit -m "docs(tls): record l4 tls http handoff target"
```

---

## Task 9: Verification and Cleanup

**Files:**
- Modify only files required by compiler/test failures.

- [ ] **Step 1: Run focused TLS tests**

Run:

```bash
cargo test -p ngfw tls::decrypted_flow tls::inspection_relay tls::mitm_proxy
```

Expected: PASS.

- [ ] **Step 2: Run policy and DPI tests**

Run:

```bash
cargo test -p ngfw dpi::classifier policy::policy_evaluator policy::engine pipeline::wrappers
```

Expected: PASS.

- [ ] **Step 3: Run full raptorgate tests**

Run:

```bash
cargo test -p ngfw
```

Expected: PASS.

- [ ] **Step 4: Check that synthetic TLS plaintext packet code is gone**

Run:

```bash
rg -n "failed to synthesize decrypted packet|build_packet_context|fn build_tcp_packet|PacketBuilder::ethernet2" crates/raptorgate/src/tls
```

Expected: no output from TLS source files.

- [ ] **Step 5: Check that TLS plaintext path does not depend on packet pipeline**

Run:

```bash
rg -n "DecryptedChainInspector|pipeline\\.process\\(|ExecutionSender|ExecutionItem|StageOutcome|PacketContext" crates/raptorgate/src/tls/decrypted_flow.rs crates/raptorgate/src/tls/inspection_relay.rs
```

Expected: no output for `DecryptedChainInspector`, `pipeline.process(`, `ExecutionSender`, `ExecutionItem`, `StageOutcome`, or `PacketContext`.

- [ ] **Step 6: Optional vagrant smoke test**

Run after deploying to the lab:

```bash
cd vagrant
vagrant ssh h2 -c "printf 'GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n' | openssl s_client -connect www.google.com:443 -servername www.google.com -quiet"
```

Expected:

- certificate chain is issued by `RaptorGate CA`,
- HTTP response is returned,
- no raw `RGDM` frame bytes appear in client output,
- r1 logs include decrypted classification and do not show synthetic packet parse warnings.

- [ ] **Step 7: Commit verification cleanup**

```bash
git status --short
git add crates/raptorgate/src
git commit -m "test(tls): verify decrypted flow inspection"
```

If there are no changes after verification, skip this commit.

---

## Self-Review Checklist

- The plan removes synthetic packet construction from TLS decrypted inspection.
- The plan keeps the normal packet path on `PacketContext`.
- The plan gives policy evaluation a shared packet-free input model.
- The plan keeps `InspectionRelay` as the TLS stream relay.
- The plan blocks the path from TLS plaintext into `ExecutionStage`.
- The plan records the later L4 target where TLS decryption emits plaintext chunks to an HTTP L4 stage.
- The plan documents that the current synchronous L4 API needs an async boundary or session-local TLS worker for full TLS MITM.
- The plan includes tests before implementation for each risky boundary.
