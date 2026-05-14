use std::sync::{Arc, Mutex};

use etherparse::{PacketBuilder, SlicedPacket};

use crate::conntrack::config::ConntrackConfig;
use crate::conntrack::observer::ObserverRegistry;
use crate::conntrack::proto::tcp::TcpHandler;
use crate::conntrack::proto::ProtoRegistry;
use crate::conntrack::table::{Conntrack, ProcessOutcome};
use crate::events::{set_event_capture, EventCapture, EventKind};
use crate::proto::events::{ConntrackPacketDirection, TcpSessionState};

static SUBSTATE_TEST_LOCK: Mutex<()> = Mutex::new(());

const C_IP: [u8; 4] = [10, 0, 0, 1];
const S_IP: [u8; 4] = [192, 0, 2, 80];
const C_PORT: u16 = 50_000;
const S_PORT: u16 = 80;

fn parse(buf: &[u8]) -> SlicedPacket<'_> {
    SlicedPacket::from_ethernet(buf).unwrap()
}

fn eth_tcp<F>(src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16, seq: u32, win: u16, f: F) -> Vec<u8>
where
    F: FnOnce(
        etherparse::PacketBuilderStep<etherparse::TcpHeader>,
    ) -> etherparse::PacketBuilderStep<etherparse::TcpHeader>,
{
    let payload = b"";
    let b = PacketBuilder::ethernet2([0u8; 6], [0u8; 6])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(sport, dport, seq, win);
    let b = f(b);
    let mut buf = Vec::with_capacity(b.size(payload.len()));
    b.write(&mut buf, payload).unwrap();
    buf
}

fn tcp_substate_steps(cap: &EventCapture) -> Vec<(TcpSessionState, TcpSessionState, ConntrackPacketDirection)> {
    cap.snapshot()
        .into_iter()
        .filter_map(|e| match e.kind {
            EventKind::TcpSessionSubstateChanged {
                previous_state,
                new_state,
                packet_direction,
                ..
            } => Some((previous_state, new_state, packet_direction)),
            _ => None,
        })
        .collect()
}

fn build_ct() -> Conntrack {
    let mut registry = ProtoRegistry::new();
    registry.register(Arc::new(TcpHandler::new(Arc::new(ObserverRegistry::default()))));
    Conntrack::new(Arc::new(registry), ConntrackConfig::default())
}

#[test]
fn tcp_substate_events_follow_handshake_and_close() {
    let _g = SUBSTATE_TEST_LOCK.lock().unwrap();
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let ct = build_ct();

    let syn = eth_tcp(C_IP, S_IP, C_PORT, S_PORT, 1000, 5840, |b| b.syn());
    let ProcessOutcome::Accept { entry, .. } = ct.process(&parse(&syn), 0) else {
        panic!("syn");
    };
    assert!(ct.confirm(&entry));

    let synack = eth_tcp(S_IP, C_IP, S_PORT, C_PORT, 2000, 5840, |b| b.syn().ack(1001));
    assert!(matches!(
        ct.process(&parse(&synack), 0),
        ProcessOutcome::Accept { .. }
    ));

    let ack = eth_tcp(C_IP, S_IP, C_PORT, S_PORT, 1001, 5840, |b| b.ack(2001));
    assert!(matches!(ct.process(&parse(&ack), 0), ProcessOutcome::Accept { .. }));

    let hello = b"hello\n";
    let mut srv_data = Vec::with_capacity(
        PacketBuilder::ethernet2([0u8; 6], [0u8; 6])
            .ipv4(S_IP, C_IP, 64)
            .tcp(S_PORT, C_PORT, 2001, 5840)
            .psh()
            .ack(1001)
            .size(hello.len()),
    );
    PacketBuilder::ethernet2([0u8; 6], [0u8; 6])
        .ipv4(S_IP, C_IP, 64)
        .tcp(S_PORT, C_PORT, 2001, 5840)
        .psh()
        .ack(1001)
        .write(&mut srv_data, hello)
        .unwrap();
    assert!(matches!(ct.process(&parse(&srv_data), 0), ProcessOutcome::Accept { .. }));

    let srv_end = 2001u32.wrapping_add(hello.len() as u32);
    let fin_c = eth_tcp(C_IP, S_IP, C_PORT, S_PORT, 1001, 5840, |b| b.fin().ack(srv_end));
    assert!(matches!(ct.process(&parse(&fin_c), 0), ProcessOutcome::Accept { .. }));

    let ack_s = eth_tcp(S_IP, C_IP, S_PORT, C_PORT, srv_end, 5840, |b| b.ack(1002));
    assert!(matches!(ct.process(&parse(&ack_s), 0), ProcessOutcome::Accept { .. }));

    let fin_s = eth_tcp(S_IP, C_IP, S_PORT, C_PORT, srv_end, 5840, |b| b.fin().ack(1002));
    assert!(matches!(ct.process(&parse(&fin_s), 0), ProcessOutcome::Accept { .. }));

    let ack_end = eth_tcp(C_IP, S_IP, C_PORT, S_PORT, 1002, 5840, |b| b.ack(srv_end.wrapping_add(1)));
    assert!(matches!(ct.process(&parse(&ack_end), 0), ProcessOutcome::Accept { .. }));

    let steps = tcp_substate_steps(&cap);
    assert_eq!(
        steps,
        vec![
            (
                TcpSessionState::SynSent,
                TcpSessionState::SynRecv,
                ConntrackPacketDirection::Reply
            ),
            (
                TcpSessionState::SynRecv,
                TcpSessionState::Established,
                ConntrackPacketDirection::Original
            ),
            (
                TcpSessionState::Established,
                TcpSessionState::FinWait,
                ConntrackPacketDirection::Original
            ),
            (
                TcpSessionState::FinWait,
                TcpSessionState::CloseWait,
                ConntrackPacketDirection::Reply
            ),
            (
                TcpSessionState::CloseWait,
                TcpSessionState::LastAck,
                ConntrackPacketDirection::Reply
            ),
            (
                TcpSessionState::LastAck,
                TcpSessionState::TimeWait,
                ConntrackPacketDirection::Original
            ),
        ]
    );

    set_event_capture(None);
}

#[test]
fn tcp_substate_no_event_when_state_unchanged_including_payload() {
    let _g = SUBSTATE_TEST_LOCK.lock().unwrap();
    let cap = Arc::new(EventCapture::new());
    set_event_capture(Some(cap.clone()));

    let ct = build_ct();

    let syn = eth_tcp(C_IP, S_IP, C_PORT, S_PORT, 1000, 5840, |b| b.syn());
    let ProcessOutcome::Accept { entry, .. } = ct.process(&parse(&syn), 0) else {
        panic!("syn");
    };
    assert!(ct.confirm(&entry));

    let synack = eth_tcp(S_IP, C_IP, S_PORT, C_PORT, 2000, 5840, |b| b.syn().ack(1001));
    ct.process(&parse(&synack), 0);

    let ack = eth_tcp(C_IP, S_IP, C_PORT, S_PORT, 1001, 5840, |b| b.ack(2001));
    ct.process(&parse(&ack), 0);

    let before_payload = tcp_substate_steps(&cap).len();

    let payload = b"payload-bytes-here";
    let mut psh = Vec::with_capacity(
        PacketBuilder::ethernet2([0u8; 6], [0u8; 6])
            .ipv4(C_IP, S_IP, 64)
            .tcp(C_PORT, S_PORT, 1001, 5840)
            .psh()
            .ack(2001)
            .size(payload.len()),
    );
    PacketBuilder::ethernet2([0u8; 6], [0u8; 6])
        .ipv4(C_IP, S_IP, 64)
        .tcp(C_PORT, S_PORT, 1001, 5840)
        .psh()
        .ack(2001)
        .write(&mut psh, payload)
        .unwrap();
    ct.process(&parse(&psh), 0);

    let after = tcp_substate_steps(&cap).len();
    assert_eq!(after, before_payload);

    set_event_capture(None);
}
