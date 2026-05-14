//! Phase 1 L4 session path — helpers and in-process scenarios (no pcap/TUN).

use std::collections::VecDeque;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use etherparse::PacketBuilder;
use ngfw::conntrack::config::ConntrackConfig;
use ngfw::conntrack::entry::ConntrackEntry;
use ngfw::conntrack::proto::udp::UdpProtoState;
use ngfw::conntrack::proto::ProtoRegistry;
use ngfw::conntrack::proto::ProtoState;
use ngfw::conntrack::session_manager::{flow_key_for, L4Input, SessionHandle, SessionManager};
use ngfw::conntrack::table::Conntrack;
use ngfw::conntrack::tuple::{Direction, FlowTuple, Protocol};
use ngfw::daemon::DataPipeline;
use ngfw::pipeline::StageOutcome;
use ngfw::data_plane::packet_context::PacketContext;

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
    let tuple = FlowTuple::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        1000,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        2000,
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

pub async fn send_two_inputs_same_flow(handle: &SessionHandle, entry: &Arc<ConntrackEntry>) {
    let p1 = sample_tcp_packet();
    let p2 = sample_tcp_packet();
    handle
        .send(L4Input {
            packet: p1,
            dir: Direction::Original,
            entry: entry.clone(),
        })
        .expect("send");
    handle
        .send(L4Input {
            packet: p2,
            dir: Direction::Reply,
            entry: entry.clone(),
        })
        .expect("send");
}

#[tokio::test]
async fn phase1_same_flow_handle_reuse() {
    let sm = phase1_session_manager();
    let e = sample_udp_entry(1001);
    let h1 = sm.handle_for_entry(&e);
    let h2 = sm.handle_for_entry(&e);
    assert_eq!(sm.active_sessions(), 1);
    drop(h1);
    drop(h2);
}

#[tokio::test]
async fn phase1_ordered_two_inputs_one_flow() {
    let log = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let ct = Arc::new(Conntrack::new(
        Arc::new(ProtoRegistry::new()),
        ConntrackConfig::default(),
    ));
    let sm = SessionManager::new_with_event_trace(
        ct,
        Default::default(),
        Default::default(),
        Default::default(),
        log.clone(),
    );
    let entry = sample_udp_entry(2002);
    let h = sm.handle_for_entry(&entry);
    send_two_inputs_same_flow(&h, &entry).await;
    drop(h);
    drop(sm);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let v = log.lock().await;
            if v.len() >= 4 {
                break;
            }
            drop(v);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timeout");
    let v = log.lock().await;
    assert_eq!(&v[..], &["open", "packet", "packet", "close"]);
}

#[tokio::test]
async fn phase1_distinct_flows_distinct_handles() {
    let sm = phase1_session_manager();
    let a = sample_udp_entry(3001);
    let b = sample_udp_entry(3002);
    let _ = sm.handle_for_entry(&a);
    let _ = sm.handle_for_entry(&b);
    assert_eq!(sm.active_sessions(), 2);
    assert_ne!(flow_key_for(&a), flow_key_for(&b));
}

#[tokio::test]
async fn testkit_daemon_v2_exposes_session_layer() {
    let td = TestDaemon::builder().build().await.expect("daemon");
    let _ = td.sessions();
}

#[tokio::test]
async fn v2_daemon_processes_packet_through_l3_chain() {
    let td = TestDaemon::builder().build().await.expect("daemon");
    
    let mut raw = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .udp(12345, 53)
        .write(&mut raw, b"test")
        .expect("packet");
    
    let output = td.daemon_v2().process_raw(raw, Arc::from("eth0")).await;
    
    assert!(
        matches!(output.stage_outcome, Some(StageOutcome::Continue) | Some(StageOutcome::Halt)),
        "expected Continue or Halt, got {:?}",
        output.stage_outcome
    );
    
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
