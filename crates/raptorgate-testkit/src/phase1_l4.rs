//! Phase 1 L4 session path — helpers and in-process scenarios (no pcap/TUN).

use std::collections::VecDeque;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use etherparse::PacketBuilder;
use ngfw::conntrack::config::ConntrackConfig;
use ngfw::conntrack::entry::ConntrackEntry;
use ngfw::conntrack::observer::DestroyReason;
use ngfw::conntrack::proto::udp::UdpProtoState;
use ngfw::conntrack::proto::ProtoRegistry;
use ngfw::conntrack::proto::ProtoState;
use ngfw::conntrack::session_manager::{flow_key_for, SessionManager};
use ngfw::conntrack::table::Conntrack;
use ngfw::conntrack::tuple::{Direction, FlowTuple, Protocol};
use ngfw::daemon::DataPipeline;
use ngfw::data_plane::dns_inspection::dnssec::DnssecProvider;
use ngfw::data_plane::packet_context::PacketContext;
use ngfw::l4::release::PacketDispositionOutcome;
use ngfw::pipeline::StageOutcome;
use ngfw::policy::engine::PolicyEngine;
use ngfw::l4::{IcmpL4PipelineFactory, UdpL4PipelineFactory};
use ngfw::zones::resolver::ZoneResolver;
use ngfw::zones::{DirectionalZonePairs, ResolvedZonePair, ZonePairId};

use crate::daemon::{TestDaemon, TestDeps};
use ngfw::events::EventCapture;
use crate::outcomes::{Expectation, PipelineOutcome};
use crate::scenario::Scenario;

#[derive(Clone)]
struct StubZoneResolver;

impl ZoneResolver for StubZoneResolver {
    fn resolve(&self, _src_interface_name: &str, _dst_ip: IpAddr) -> Option<ResolvedZonePair> {
        Some(ResolvedZonePair {
            id: ZonePairId::from(uuid::Uuid::nil()),
            default_policy: ngfw::zones::DefaultPolicy::Allow,
        })
    }

    fn resolve_bidirectional(&self, _src_ip: IpAddr, _dst_ip: IpAddr) -> DirectionalZonePairs {
        let pair = ResolvedZonePair {
            id: ZonePairId::from(uuid::Uuid::nil()),
            default_policy: ngfw::zones::DefaultPolicy::Allow,
        };
        DirectionalZonePairs {
            forward: Some(pair.clone()),
            reverse: Some(pair),
        }
    }
}

struct NoDnssec;

impl DnssecProvider for NoDnssec {
    fn check_domain(
        &self,
        _domain: &str,
        _qtype: Option<ngfw::dpi::parsers::dns::DnsRecordType>,
    ) -> ngfw::data_plane::dns_inspection::dnssec::DnssecResult {
        ngfw::data_plane::dns_inspection::dnssec::DnssecResult::not_checked()
    }
}

fn phase1_session_manager() -> (
    Arc<SessionManager<StubZoneResolver, NoDnssec>>,
    tokio::sync::mpsc::UnboundedReceiver<ngfw::l4::ReleaseAction>,
) {
    let ct = Arc::new(Conntrack::new(
        Arc::new(ProtoRegistry::new()),
        ConntrackConfig::default(),
    ));
    let (release_tx, release_rx) = tokio::sync::mpsc::unbounded_channel();
    let policies = std::collections::HashMap::new();
    let zone_pairs = std::collections::HashMap::new();
    let policy_engine =
        Arc::new(PolicyEngine::from_policies(&policies, &zone_pairs).expect("policy engine"));
    let sm = SessionManager::new(
        ct,
        Default::default(),
        UdpL4PipelineFactory::default(),
        IcmpL4PipelineFactory::default(),
        policy_engine,
        StubZoneResolver,
        None,
        None,
        None,
        release_tx,
    );
    (sm, release_rx)
}

pub fn sample_udp_entry(id: u64) -> Arc<ConntrackEntry> {
    sample_udp_flow(id, 1000, 2000)
}

pub fn sample_udp_flow(id: u64, src_port: u16, dst_port: u16) -> Arc<ConntrackEntry> {
    let tuple = FlowTuple::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        dst_port,
        Protocol::Udp,
    );

    Arc::new(ConntrackEntry::new(
        id,
        tuple,
        ProtoState::Udp(UdpProtoState::default()),
        Duration::from_secs(60),
        0,
    ))
}

pub fn sample_tcp_packet() -> PacketContext {
    let mut raw = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 80, 1, 65535)
        .write(&mut raw, b"p")
        .expect("packet");
    PacketContext::from_raw(raw, Arc::from("eth0")).expect("packet")
}

#[tokio::test]
async fn phase1_confirm_idempotent_one_session() {
    let (sm, _rx) = phase1_session_manager();
    let ct = sm.conntrack().clone();
    let e = sample_udp_entry(1001);
    assert!(ct.confirm(&e));
    assert_eq!(sm.active_sessions(), 1);
    assert!(ct.confirm(&e));
    assert_eq!(sm.active_sessions(), 1);
    ct.destroy(&e, DestroyReason::Manual);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if sm.active_sessions() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timeout waiting for session cleanup");
}

#[tokio::test]
async fn phase1_ordered_two_inputs_one_flow() {
    let log = Arc::new(StdMutex::new(Vec::new()));
    let ct = Arc::new(Conntrack::new(
        Arc::new(ProtoRegistry::new()),
        ConntrackConfig::default(),
    ));
    let (release_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let policies = std::collections::HashMap::new();
    let zone_pairs = std::collections::HashMap::new();
    let policy_engine =
        Arc::new(PolicyEngine::from_policies(&policies, &zone_pairs).expect("policy engine"));
    let sm = SessionManager::<StubZoneResolver, NoDnssec>::new_with_event_trace(
        ct.clone(),
        Default::default(),
        UdpL4PipelineFactory::default(),
        IcmpL4PipelineFactory::default(),
        log.clone(),
        policy_engine,
        StubZoneResolver,
        None,
        None,
        None,
        release_tx,
    );
    let entry = sample_udp_entry(2002);
    assert!(ct.confirm(&entry));

    let mut original_raw = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(1000, 2000)
        .write(&mut original_raw, b"x")
        .expect("packet");
    let original_packet = PacketContext::from_raw(original_raw, Arc::from("eth0")).expect("packet");
    let original_pid = original_packet.packet_id();
    sm.admit_packet(&entry, original_packet, Direction::Original);
    sm.inject_session_payload(&entry, Direction::Original, b"x", original_pid);

    let mut reply_raw = Vec::new();
    PacketBuilder::ethernet2([7, 8, 9, 10, 11, 12], [1, 2, 3, 4, 5, 6])
        .ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
        .udp(2000, 1000)
        .write(&mut reply_raw, b"y")
        .expect("packet");
    let reply_packet = PacketContext::from_raw(reply_raw, Arc::from("eth1")).expect("packet");
    let reply_pid = reply_packet.packet_id();
    sm.admit_packet(&entry, reply_packet, Direction::Reply);
    sm.inject_session_payload(&entry, Direction::Reply, b"y", reply_pid);
    ct.destroy(&entry, DestroyReason::Manual);

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let v = log.lock().expect("trace");
            if v.len() >= 4 {
                break;
            }
            drop(v);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timeout");

    let v = log.lock().expect("trace");
    assert_eq!(&v[..], &["open", "bytes", "bytes", "close"]);
}

#[tokio::test]
async fn phase1_distinct_flows_distinct_sessions() {
    let (sm, _rx) = phase1_session_manager();
    let ct = sm.conntrack().clone();
    let a = sample_udp_entry(3001);
    let b = sample_udp_flow(3002, 1001, 2000);
    assert!(ct.confirm(&a));
    assert!(ct.confirm(&b));
    assert_eq!(sm.active_sessions(), 2);
    assert_ne!(flow_key_for(&a), flow_key_for(&b));
    ct.destroy(&a, DestroyReason::Manual);
    ct.destroy(&b, DestroyReason::Manual);
}

#[tokio::test]
async fn phase1_invalidate_via_session_context() {
    let log = Arc::new(StdMutex::new(Vec::new()));
    let ct = Arc::new(Conntrack::new(
        Arc::new(ProtoRegistry::new()),
        ConntrackConfig::default(),
    ));
    let (release_tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let policies = std::collections::HashMap::new();
    let zone_pairs = std::collections::HashMap::new();
    let policy_engine =
        Arc::new(PolicyEngine::from_policies(&policies, &zone_pairs).expect("policy engine"));
    let sm = SessionManager::<StubZoneResolver, NoDnssec>::new_with_event_trace(
        ct.clone(),
        Default::default(),
        UdpL4PipelineFactory::default(),
        IcmpL4PipelineFactory::default(),
        log.clone(),
        policy_engine,
        StubZoneResolver,
        None,
        None,
        None,
        release_tx,
    );
    let entry = sample_udp_entry(4001);
    assert!(ct.confirm(&entry));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let ready = log
                .lock()
                .map(|v| !v.is_empty() && v[0] == "open")
                .unwrap_or(false);
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timeout waiting for session open");
    sm.invalidate_session(&flow_key_for(&entry));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let done = {
                let v = log.lock().expect("trace");
                v.len() >= 2 && v[0] == "open" && v[1] == "close"
            };
            if done {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timeout");

    let v = log.lock().expect("trace");
    assert_eq!(&v[..], &["open", "close"]);
}

#[tokio::test]
async fn phase1_release_rx_forward_matches_packet_id() {
    let (sm, mut release_rx) = phase1_session_manager();
    let ct = sm.conntrack().clone();
    let entry = sample_udp_entry(5001);
    assert!(ct.confirm(&entry));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if sm.has_session_handle(&entry) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timeout waiting for session handle");

    let mut raw = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(1000, 2000)
        .write(&mut raw, b"p")
        .expect("packet");
    let packet = PacketContext::from_raw(raw, Arc::from("eth0")).expect("packet");
    let pid = packet.packet_id();
    sm.admit_packet(&entry, packet, Direction::Original);
    sm.inject_session_payload(&entry, Direction::Original, b"x", pid);

    let action = tokio::time::timeout(Duration::from_secs(2), release_rx.recv())
        .await
        .expect("timeout waiting for release")
        .expect("release channel closed");

    match action {
        ngfw::l4::ReleaseAction::Forward { packet } => {
            assert_eq!(packet.packet_id(), pid);
        }
        other => panic!("expected Forward, got {other:?}"),
    }

    ct.destroy(&entry, DestroyReason::Manual);
}

#[tokio::test]
async fn testkit_daemon_v2_exposes_session_layer() {
    let td = TestDaemon::builder().build().await.expect("daemon");
    let _ = td.sessions();
}

#[tokio::test]
async fn v2_daemon_processes_packet_through_l3_chain() {
    let td = TestDaemon::builder().build().await.expect("daemon");
    let cap = Arc::new(EventCapture::new());

    let mut raw = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(12345, 53)
        .write(&mut raw, b"test")
        .expect("packet");

    Scenario::packets()
        .on_iface("eth0")
        .send(raw)
        .expect_packet(Expectation::Pipeline(PipelineOutcome::Forwarded))
        .run_v2(&td, &cap)
        .await
        .expect("packet processed");

    let events = td.sessions().observer_event_count();
    assert!(events > 0, "expected observer events from conntrack, got {}", events);
}

#[test]
fn production_stage_outcome_release_batch_still_exists() {
    let q: VecDeque<PacketContext> = VecDeque::new();
    let o = StageOutcome::ReleaseBatch(q);
    assert!(matches!(o, StageOutcome::ReleaseBatch(_)));
}

#[test]
fn production_data_pipeline_type_alias_holds() {
    let _ = PhantomData::<DataPipeline<TestDeps>>;
}
