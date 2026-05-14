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
use ngfw::data_plane::packet_context::PacketContext;
use ngfw::pipeline::StageOutcome;

use crate::daemon::{TestDaemon, TestDeps};

pub fn phase1_session_manager() -> Arc<SessionManager> {
    let ct = Arc::new(Conntrack::new(
        Arc::new(ProtoRegistry::new()),
        ConntrackConfig::default(),
    ));
    SessionManager::new(
        ct,
        Default::default(),
        Default::default(),
        Default::default(),
    )
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
    let sm = phase1_session_manager();
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
    let sm = SessionManager::new_with_event_trace(
        ct.clone(),
        Default::default(),
        Default::default(),
        Default::default(),
        log.clone(),
    );
    let entry = sample_udp_entry(2002);
    assert!(ct.confirm(&entry));
    sm.inject_session_payload(&entry, Direction::Original, b"x");
    sm.inject_session_payload(&entry, Direction::Reply, b"y");
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
    let sm = phase1_session_manager();
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
    let sm = SessionManager::new_with_event_trace(
        ct.clone(),
        Default::default(),
        Default::default(),
        Default::default(),
        log.clone(),
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
    let ctx = ngfw::conntrack::session_manager::SessionContext::snapshot(&entry, &sm);
    ctx.invalidate();

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
async fn testkit_daemon_v2_exposes_session_layer() {
    let td = TestDaemon::builder().build().await.expect("daemon");
    let _ = td.sessions();
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
