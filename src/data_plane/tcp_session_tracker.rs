use std::{marker::PhantomData, net::IpAddr, pin::Pin, sync::Arc, time::{Duration, Instant}};

use bitflags::{bitflags, bitflags_match};
use dashmap::{DashMap, Entry};
use derive_more::{Add, AddAssign, Display, From, Into};
use etherparse::{IpPayloadSlice, Ipv4Slice, NetSlice, SlicedPacket, TcpSlice, TransportSlice, err::tcp::HeaderSliceError};
use ngfw::frame::RealFrame;
use ringbuffer::{AllocRingBuffer, RingBuffer};
use thiserror::Error;
use unordered_pair::UnorderedPair;

use crate::frame::{Frame, Port};

pub struct TcpSessionTracker {
    sessions: Arc<DashMap<TcpIdentifier, TcpSession>>, //TODO: Transition away from using `Arc` since we want to avoid indirection, do something like in `PacketBuffer`.
    buffer: Arc<PacketBuffer>,
}

#[derive(Debug, Clone)]
struct TcpPacketInfo {
    flags: TcpFlags,
    sequence_number: SeqNumber,
    acknowledgment_number: AckNumber,
    window_size: u16,
    payload_size: u16,
    src: EndpointIdentifier,
    dst: EndpointIdentifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, From, Add, AddAssign, Display, Into)]
struct AckNumber(u32);

impl AckNumber {
    fn wrapping_add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    fn wrapping_sub(self, rhs: u32) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }
}

impl From<SeqNumber> for AckNumber {
    fn from(seq: SeqNumber) -> Self {
        Self(seq.0)
    }
}

impl PartialEq<SeqNumber> for AckNumber {
    fn eq(&self, other: &SeqNumber) -> bool {
        self.0 == other.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, From, Add, AddAssign, Display, Into)]
struct SeqNumber(u32);

impl SeqNumber {
    fn wrapping_add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    fn wrapping_sub(self, rhs: u32) -> Self {
        Self(self.0.wrapping_sub(rhs))
    }

    fn is_between_wrapped(self, lo: SeqNumber, hi: SeqNumber) -> bool {
        if lo.0 <= hi.0 {
            self.0 >= lo.0 && self.0 <= hi.0
        } else {
            self.0 >= lo.0 || self.0 <= hi.0
        }
    }
}

impl PartialEq<AckNumber> for SeqNumber {
    fn eq(&self, other: &AckNumber) -> bool {
        self.0 == other.0
    }
}

impl From<AckNumber> for SeqNumber {
    fn from(ack: AckNumber) -> Self {
        Self(ack.0)
    }
}

impl TcpPacketInfo {
    fn new(tcp: &TcpSlice, src: EndpointIdentifier, dst: EndpointIdentifier) -> Result<Self, TcpSessionError> {
        let flag_start = tcp.header_slice()[TcpOffsets::FLAGS];
        let flag_end = tcp.header_slice()[TcpOffsets::FLAGS + 1];

        let raw = ((flag_start & 0x01) as u16) << 8 | (flag_end as u16);
        let Some(flags) = TcpFlags::from_bits(raw) else { return Err(TcpSessionError::ZeroFlagPacket); /*FIXME: placeholder error*/ };
        Ok(Self {
            flags,
            sequence_number: tcp.sequence_number().into(),
            acknowledgment_number: tcp.acknowledgment_number().into(),
            window_size: tcp.window_size(),
            src,
            dst,
            payload_size: tcp.payload().len() as u16,
        })
    }
}

impl TcpSessionTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Arc::new(DashMap::new()),
            buffer: PacketBuffer::new(),
        })
    }

    pub fn process_packet(&self, packet: &SlicedPacket) -> Result<Option<TcpSessionState>, TcpSessionError> {
        match &packet.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let header = ipv4.header();
                match &packet.transport {
                    Some(TransportSlice::Tcp(tcp)) => {
                        let src = EndpointIdentifier {
                            ip: IpAddr::V4(header.source_addr()),
                            port: Port::from(tcp.source_port()),
                        };
                        let dst = EndpointIdentifier {
                            ip: IpAddr::V4(header.destination_addr()),
                            port: Port::from(tcp.destination_port()),
                        };
                        let tcp_info = TcpPacketInfo::new(&tcp, src, dst)?;
                        self.process_tcp(tcp_info)
                    }
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    fn process_tcp(&self, packet: TcpPacketInfo) -> Result<Option<TcpSessionState>, TcpSessionError> {
        let endpoints = (
            packet.src.clone(),
            packet.dst.clone(),
        );

        let id = TcpIdentifier {
            endpoints: UnorderedPair::from(endpoints.clone()),
        };

        let entry = self.sessions.entry(id.clone());

        match entry {
            Entry::Occupied(mut e) => {
                let session = e.get_mut();

                self.process_session_state(session, packet, &id)
            }

            Entry::Vacant(e) => {
                bitflags_match!(&packet.flags, {
                    &TcpFlags::SYN => { 
                        let inserted = e.insert(TcpSession::new(
                            TcpSessionState::Handshake(TcpHandshakeState::SynSent),
                            Endpoint { id: packet.src.clone(), next_expected_seq: packet.sequence_number.wrapping_add(1), max_window_size: packet.window_size},
                            Endpoint { id: packet.dst.clone(), next_expected_seq: 0.into(), max_window_size: 0 },
                        ));

                        self.process_from_buffer(inserted.key(), Some(TcpFlags::SYN | TcpFlags::ACK), Some(&packet.dst))?;

                        // if let Some(session) = self.buffer.get_session(&id) {
                        //     for p in session.value().iter() {
                        //         self.process_packet(p.clone())?;
                        //     }
                        // }

                        Ok(Some(TcpSessionState::Handshake(TcpHandshakeState::SynSent)))
                    },

                    _ => { 
                        self.buffer.add_packet(id.clone(), packet.clone())?;
                        Ok(None)
                    },
                })
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn process_session_state(&self, session: &mut TcpSession, packet: TcpPacketInfo, id: &TcpIdentifier) -> Result<Option<TcpSessionState>, TcpSessionError> {
        match session.state {
            TcpSessionState::Handshake(s) => match s {
                TcpHandshakeState::SynSent => {
                    if packet.flags.contains(TcpFlags::SYN | TcpFlags::ACK)
                        && packet.src == session.receiver.id 
                            && packet.acknowledgment_number == session.initiator.next_expected_seq {
                                session.receiver.next_expected_seq = packet.sequence_number.wrapping_add(1);
                                session.receiver.max_window_size = packet.window_size;
                                session.state = TcpSessionState::Handshake(TcpHandshakeState::SynAckReceived);

                                self.process_from_buffer(id, Some(TcpFlags::ACK), Some(&session.initiator.id))?;
                    }
                },

                TcpHandshakeState::SynAckReceived => {
                    if packet.flags.contains(TcpFlags::ACK)
                        && packet.src == session.initiator.id
                            && packet.sequence_number == session.initiator.next_expected_seq
                            && packet.acknowledgment_number == session.receiver.next_expected_seq {
                                session.initiator.next_expected_seq = session.initiator.next_expected_seq.wrapping_add(u32::from(packet.payload_size));
                                session.state = TcpSessionState::Established;

                                self.process_from_buffer(id, None, None)?;
                    }
                },

            },
            TcpSessionState::Established => {
                if packet.flags.contains(TcpFlags::RST) {
                    self.sessions.remove(id);
                    return Ok(Some(TcpSessionState::Closed));
                }

                if packet.flags.contains(TcpFlags::SYN) {
                    return Err(TcpSessionError::InvalidFlagOnSessionState { flags: TcpFlags::SYN, state: TcpSessionState::Established });
                }

                if !packet.flags.contains(TcpFlags::ACK) {
                    return Err(TcpSessionError::InvalidFlagOnSessionState { flags: packet.flags, state: TcpSessionState::Established }); //TODO: this should probably be handled differently
                }

                let mut saw_fin = false;
                // TODO: shit lang
                {
                    let (sender, receiver) = Self::get_endpoints_of_session_packet(
                        &packet.src,
                        &mut session.initiator,
                        &mut session.receiver,
                    );

                    let lo = sender.next_expected_seq.wrapping_sub(REORDER_TOLERANCE);
                    let hi = sender.next_expected_seq.wrapping_add(receiver.max_window_size.into());

                    if !packet.sequence_number.is_between_wrapped(lo, hi) {
                        return Err(TcpSessionError::OutOfWindow { lo: lo.into(), hi: hi.into(), seq: packet.sequence_number.into() });
                    }

                    sender.next_expected_seq = sender.next_expected_seq
                        .wrapping_add(u32::from(packet.payload_size));

                    if packet.flags.contains(TcpFlags::FIN) {
                        sender.next_expected_seq = sender.next_expected_seq.wrapping_add(1);
                        saw_fin = true;
                    }
                }

                if saw_fin {
                    session.state = TcpSessionState::Closing(TcpClosingState::FinSent);
                    session.set_closing_initiator(&packet.src);
                    self.process_from_buffer(id, Some(TcpFlags::ACK), Some(&packet.src))?;
                }
            }

            TcpSessionState::Closing(closing_state) => {
                let closing_initiator = session.get_closing_initiator();
                let (initiator, responder) = if closing_initiator.id == session.initiator.id {
                    (&mut session.initiator, &mut session.receiver)
                } else {
                    (&mut session.receiver, &mut session.initiator)
                };

                let (sender, _receiver) = Self::get_endpoints_of_session_packet(
                    &packet.src,
                    initiator,
                    responder,
                );

                sender.next_expected_seq = sender
                    .next_expected_seq
                    .wrapping_add(u32::from(packet.payload_size));

                if packet.flags.contains(TcpFlags::FIN) {
                    sender.next_expected_seq = sender.next_expected_seq.wrapping_add(1);
                }

                match closing_state {
                    TcpClosingState::FinSent => {
                        if packet.flags.contains(TcpFlags::FIN | TcpFlags::ACK)
                            && packet.src == responder.id
                            && packet.acknowledgment_number == initiator.next_expected_seq
                        {
                            session.state = TcpSessionState::Closing(TcpClosingState::AckFinSent);
                            self.process_from_buffer(id, Some(TcpFlags::ACK), Some(&initiator.id))?;
                        } else if packet.flags.contains(TcpFlags::ACK)
                            && packet.src == responder.id
                            && packet.acknowledgment_number == initiator.next_expected_seq
                        {
                            session.state = TcpSessionState::Closing(TcpClosingState::AckSent);
                            self.process_from_buffer(id, Some(TcpFlags::FIN), Some(&responder.id))?;
                        }
                    }

                    TcpClosingState::AckSent => {
                        if packet.flags.contains(TcpFlags::FIN)
                            && packet.src == responder.id
                            && packet.acknowledgment_number == initiator.next_expected_seq
                        {
                            session.state = TcpSessionState::Closing(TcpClosingState::AckFinSent);
                            self.process_from_buffer(id, Some(TcpFlags::ACK), Some(&initiator.id))?;
                        }
                    }

                    TcpClosingState::AckFinSent => {
                        if packet.flags.contains(TcpFlags::ACK)
                            && packet.src == initiator.id
                            && packet.acknowledgment_number == responder.next_expected_seq
                        {
                            session.state = TcpSessionState::TimeWait;
                        }
                    }
                }
            }

            TcpSessionState::TimeWait => {
                if packet.flags.contains(TcpFlags::RST) {
                    self.sessions.remove(id);
                    return Ok(Some(TcpSessionState::Closed));
                }
            }

            TcpSessionState::Closed => unreachable!() //TODO: separate return type and the state that the session can actually be in
        }

        Ok(Some(session.state))
    }

    fn schedule_timewait_cleanup(&self, id: &TcpIdentifier) {
        let sessions = self.sessions.clone();
        let id = id.clone();

        tokio::spawn(async move {
            tokio::time::sleep(TIME_WAIT_TIMEOUT).await;
            if let Some(entry) = sessions.get(&id) && entry.state == TcpSessionState::TimeWait {
                drop(entry);
                sessions.remove(&id);
            }
        });
    }

    fn get_endpoints_of_session_packet<'a>(
        src: &EndpointIdentifier,
        initiator: &'a mut Endpoint,
        receiver: &'a mut Endpoint,
    ) -> (&'a mut Endpoint, &'a mut Endpoint) {
        if *src == initiator.id {
            (initiator, receiver)
        } else {
            (receiver, initiator)
        }
    }

    fn process_from_buffer(&self, session_id: &TcpIdentifier, flags: Option<TcpFlags>, from: Option<&EndpointIdentifier>) -> Result<(), TcpSessionError> {
        let packets: Vec<TcpPacketInfo> = if let Some(session) = self.buffer.get_session(session_id) {
            session.iter()
                .filter(|&p| {
                    let flag_match = flags.as_ref().is_none_or(|f| p.flags == *f);
                    let from_match = from.is_none_or(|f| &p.src == f);
                    flag_match && from_match
                })
            .cloned()
                .collect()
        } else {
            return Ok(());
        };

        for packet in packets {
            self.process_tcp(packet)?;
        }

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum TcpSessionError {
    #[error("Packet with no flags")]
    ZeroFlagPacket,

    #[error("Buffer error: {0}")]
    BufferError(#[from] PacketBufferError),

    #[error("Invalid flags {flags:?} on state {state:?}")]
    InvalidFlagOnSessionState { flags: TcpFlags, state: TcpSessionState },

    #[error("Packet sequence number {seq} out of window ({lo}, {hi})")]
    OutOfWindow {lo: u32, hi: u32, seq: u32},
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TcpIdentifier {
    endpoints: UnorderedPair<EndpointIdentifier>
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
struct EndpointIdentifier {
    ip: IpAddr,
    port: Port,
}

#[derive(Debug)]
struct Endpoint {
    id: EndpointIdentifier,
    next_expected_seq: SeqNumber,
    max_window_size: u16,
}

struct PacketBuffer {
    waiting: DashMap<TcpIdentifier, SessionPackets>,
}

impl PacketBuffer {
    pub fn new() -> Arc<Self> {
        let buffer = Arc::new(Self {
            waiting: DashMap::new(),
        });

        let sweeper: std::sync::Weak<Self> = Arc::downgrade(&buffer);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PENDING_TIMEOUT);
            loop {
                interval.tick().await;
                if let Some(target) = sweeper.upgrade() {
                    target.sweep();
                } else {
                    break;
                }
            }
        });

        buffer
    }

    fn sweep(&self) {
        self.waiting.retain(|_, v| {
            v.first_packet_arrival.elapsed() < PENDING_TIMEOUT
        });
    }

    fn add_packet(&self, id: TcpIdentifier, tcp: TcpPacketInfo) -> Result<(), PacketBufferError>  {
        // we preallocate the buffers for each session so we can perform a simple check like this
        let is_full = self.waiting.len() * PENDING_PACKETS_PER_SESSION >= MAX_PENDING_PACKETS;

        match self.waiting.entry(id) {
            Entry::Occupied(mut occupied) => {
                if occupied.get().first_packet_arrival.elapsed() > PENDING_TIMEOUT {
                    occupied.remove_entry();
                    return Err(PacketBufferError::SessionExpired);
                }

                occupied.get_mut().packets.enqueue(tcp);
                Ok(())
            }

            Entry::Vacant(vacant) => {
                if is_full {
                    return Err(PacketBufferError::BufferFull);
                }

                let mut session_packets = SessionPackets::new(Instant::now());

                session_packets.packets.enqueue(tcp);
                vacant.insert(session_packets);
                Ok(())
            }
        }
    }

    fn get_session(&self, id: &TcpIdentifier) -> Option<dashmap::mapref::one::Ref<'_, TcpIdentifier, SessionPackets>> {
        self.waiting.get(id)
    }
}

bitflags! {
    #[derive(Debug, PartialEq, Clone)]
    pub struct TcpFlags: u16 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
        const URG = 0x20;
        const ECE = 0x40;
        const CWR = 0x80;
        const NS  = 0x100;
    }
}


const MAX_PENDING_PACKETS: usize = 4096;
const PENDING_TIMEOUT: Duration = Duration::from_millis(250);
const PENDING_PACKETS_PER_SESSION: usize = 16;
const PAYLOAD_MAX_SIZE: u32 = 1460;
const REORDER_TOLERANCE: u32 = 3 * PAYLOAD_MAX_SIZE;
const TIME_WAIT_TIMEOUT: Duration = Duration::from_secs(60);


struct SessionPackets {
    packets: AllocRingBuffer<TcpPacketInfo>,
    first_packet_arrival: Instant,
}

impl SessionPackets {
    fn new(arrival_time: Instant) -> Self {
        Self {
            packets: AllocRingBuffer::new(PENDING_PACKETS_PER_SESSION),
            first_packet_arrival: arrival_time,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &TcpPacketInfo> {
        self.packets.iter()
    }
}


enum TcpOffsets {}

impl TcpOffsets {
    pub const FLAGS: usize = 12;
}


struct TcpSession {
    state: TcpSessionState,
    initiator: Endpoint,
    receiver: Endpoint,
    closing_initiator: Option<ClosingInitiator>,
}

impl TcpSession {
    fn new(state: TcpSessionState, initiator: Endpoint, receiver: Endpoint) -> Self {
        Self {
            state,
            initiator,
            receiver,
            closing_initiator: None,
        }
    }

    fn get_closing_initiator(&self) -> &Endpoint {
        let initiator = self.closing_initiator.as_ref().expect("calling `get_closing_initiator` on an invalid object. This should be refactored in the future");

        match initiator {
            ClosingInitiator::Initiator => &self.initiator,
            ClosingInitiator::Receiver => &self.receiver,
        }
    }

    fn set_closing_initiator(&mut self, src: &EndpointIdentifier) {
        self.closing_initiator = Some(if *src == self.initiator.id {
            ClosingInitiator::Initiator
        } else {
            ClosingInitiator::Receiver
        });
    }
}

enum ClosingInitiator {
    Initiator,
    Receiver,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSessionState {
    Handshake(TcpHandshakeState),
    Established,
    Closed,
    Closing(TcpClosingState),
    TimeWait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHandshakeState {
    SynSent,
    SynAckReceived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpClosingState {
    FinSent,
    AckSent,
    AckFinSent,
}

#[derive(Error, Debug)]
pub enum PacketBufferError {
    #[error("TCP session expired")]
    SessionExpired,
    #[error("Packet buffer full")]
    BufferFull,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn client() -> EndpointIdentifier {
        EndpointIdentifier {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: Port::from(12345u16),
        }
    }

    fn server() -> EndpointIdentifier {
        EndpointIdentifier {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            port: Port::from(443u16),
        }
    }

    fn make_packet(
        src: EndpointIdentifier,
        dst: EndpointIdentifier,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        window: u16,
        payload: u16,
    ) -> TcpPacketInfo {
        TcpPacketInfo {
            flags,
            sequence_number: SeqNumber(seq),
            acknowledgment_number: AckNumber(ack),
            window_size: window,
            payload_size: payload,
            src,
            dst,
        }
    }

    fn session_id() -> TcpIdentifier {
        TcpIdentifier {
            endpoints: UnorderedPair::from((client(), server())),
        }
    }

    fn mk_id(i: usize) -> TcpIdentifier {
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let src_port = Port::from((10_000 + (i % 50_000)) as u16);
        let dst_port = Port::from(443);

        TcpIdentifier {
            endpoints: UnorderedPair::from((
                               EndpointIdentifier { ip: src_ip, port: src_port },
                               EndpointIdentifier { ip: dst_ip, port: dst_port },
                       )),
        }
    }

    fn mk_tcp_info(i: usize) -> TcpPacketInfo {
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        TcpPacketInfo {
            flags: TcpFlags::SYN,
            sequence_number: SeqNumber(1),
            acknowledgment_number: AckNumber(0),
            window_size: 1024,
            payload_size: 0,
            src: EndpointIdentifier { ip: src_ip, port: Port::from(12_345) },
            dst: EndpointIdentifier { ip: dst_ip, port: Port::from(443) },
        }
    }

    #[tokio::test]
    async fn establishes_new_session_on_first_packet() {
        let buffer = PacketBuffer::new();
        let id = mk_id(1);

        assert_eq!(buffer.waiting.len(), 0);
        let res = buffer.add_packet(id.clone(), mk_tcp_info(1));
        assert!(res.is_ok());
        assert_eq!(buffer.waiting.len(), 1);
        assert!(buffer.waiting.contains_key(&id));
    }

    #[tokio::test]
    async fn cleans_up_sessions_after_timeout() {
        let buffer = PacketBuffer::new();
        let id = mk_id(2);

        buffer.add_packet(id.clone(), mk_tcp_info(2)).unwrap();
        assert!(buffer.waiting.contains_key(&id));

        tokio::time::sleep(PENDING_TIMEOUT + Duration::from_millis(20)).await;
        buffer.sweep();

        assert!(!buffer.waiting.contains_key(&id));
        assert_eq!(buffer.waiting.len(), 0);
    }

    #[tokio::test]
    async fn returns_buffer_full_when_capacity_exceeded() {
        let buffer = PacketBuffer::new();
        let max_sessions = MAX_PENDING_PACKETS / PENDING_PACKETS_PER_SESSION;

        for i in 0..max_sessions {
            let res = buffer.add_packet(mk_id(i), mk_tcp_info(i));
            assert!(res.is_ok(), "expected fill to succeed at {i}");
        }

        let overflow = buffer.add_packet(mk_id(max_sessions + 1), mk_tcp_info(max_sessions + 1));
        match overflow {
            Err(PacketBufferError::BufferFull) => {}
            _ => panic!("expected PacketBufferError::BufferFull"),
        }
    }

    #[tokio::test]
    async fn full_tcp_session_lifecycle() {
        let tracker: Arc<TcpSessionTracker> = TcpSessionTracker::new();
        let id = session_id();

        // ── 1. SYN from client ───────────────────────────────────────────────
        // Client ISN = 1000. Firewall stores next_expected_seq = 1001.
        let result = tracker.process_tcp(make_packet(
                client(), server(), TcpFlags::SYN, 1000, 0, 8192, 0,
        ));
        assert_eq!(
            result.unwrap(),
            Some(TcpSessionState::Handshake(TcpHandshakeState::SynSent))
        );
        {
            let s = tracker.sessions.get(&id).unwrap();
            assert_eq!(s.initiator.next_expected_seq, SeqNumber(1001), "initiator seq after SYN");
            assert_eq!(s.receiver.next_expected_seq, SeqNumber(0),    "receiver seq unknown after SYN");
        }

        // ── 2. SYN-ACK from server ───────────────────────────────────────────
        // Server ISN = 5000, ACK = 1001 (client ISN + 1).
        // Firewall stores receiver.next_expected_seq = 5001.
        let result = tracker.process_tcp(make_packet(
                server(), client(), TcpFlags::SYN | TcpFlags::ACK, 5000, 1001, 8192, 0,
        ));
        assert_eq!(
            result.unwrap(),
            Some(TcpSessionState::Handshake(TcpHandshakeState::SynAckReceived))
        );
        {
            let s = tracker.sessions.get(&id).unwrap();
            assert_eq!(s.initiator.next_expected_seq, SeqNumber(1001), "initiator seq unchanged after SYN-ACK");
            assert_eq!(s.receiver.next_expected_seq,  SeqNumber(5001), "receiver seq after SYN-ACK");
            assert_eq!(s.receiver.max_window_size,    8192,            "receiver window after SYN-ACK");
        }

        // ── 3. ACK from client (handshake complete) ──────────────────────────
        // seq=1001, ack=5001. No payload, so initiator.next_expected_seq stays 1001.
        let result = tracker.process_tcp(make_packet(
                client(), server(), TcpFlags::ACK, 1001, 5001, 8192, 0,
        ));
        assert_eq!(result.unwrap(), Some(TcpSessionState::Established));
        {
            let s = tracker.sessions.get(&id).unwrap();
            assert_eq!(s.initiator.next_expected_seq, SeqNumber(1001), "initiator seq after final ACK");
            assert_eq!(s.receiver.next_expected_seq,  SeqNumber(5001), "receiver seq after final ACK");
        }

        // ── 4. Data from client (100 bytes) ──────────────────────────────────
        // seq=1001, payload=100. initiator.next_expected_seq advances to 1101.
        let result = tracker.process_tcp(make_packet(
                client(), server(), TcpFlags::ACK, 1001, 5001, 8192, 100,
        ));
        assert_eq!(result.unwrap(), Some(TcpSessionState::Established));
        {
            let s = tracker.sessions.get(&id).unwrap();
            assert_eq!(s.initiator.next_expected_seq, SeqNumber(1101), "initiator seq after 100 bytes");
        }

        // ── 5. Data from server (50 bytes) ───────────────────────────────────
        // seq=5001, payload=50. receiver.next_expected_seq advances to 5051.
        let result = tracker.process_tcp(make_packet(
                server(), client(), TcpFlags::ACK, 5001, 1101, 8192, 50,
        ));
        assert_eq!(result.unwrap(), Some(TcpSessionState::Established));
        {
            let s = tracker.sessions.get(&id).unwrap();
            assert_eq!(s.receiver.next_expected_seq, SeqNumber(5051), "receiver seq after 50 bytes");
        }

        // ── 6. FIN|ACK from client ────────────────────────────────────────────
        // FIN consumes one seq number → initiator.next_expected_seq = 1102.
        let result = tracker.process_tcp(make_packet(
                client(), server(), TcpFlags::FIN | TcpFlags::ACK, 1101, 5051, 8192, 0,
        ));
        assert_eq!(
            result.unwrap(),
            Some(TcpSessionState::Closing(TcpClosingState::FinSent))
        );
        {
            let s = tracker.sessions.get(&id).unwrap();
            assert_eq!(s.initiator.next_expected_seq, SeqNumber(1102), "initiator seq after FIN");
        }

        // ── 7. ACK from server ────────────────────────────────────────────────
        // Server ACKs client's FIN. ack=1102.
        let result = tracker.process_tcp(make_packet(
                server(), client(), TcpFlags::ACK, 5051, 1102, 8192, 0,
        ));
        assert_eq!(
            result.unwrap(),
            Some(TcpSessionState::Closing(TcpClosingState::AckSent))
        );

        // ── 8. FIN|ACK from server ────────────────────────────────────────────
        // Server sends its own FIN. FIN consumes a seq → receiver.next_expected_seq should be 5052.
        // NOTE: the closing handler does not currently increment seq for FIN the way
        // Established does — this test will fail here, exposing that bug.
        let result = tracker.process_tcp(make_packet(
                server(), client(), TcpFlags::FIN | TcpFlags::ACK, 5051, 1102, 8192, 0,
        ));
        assert_eq!(
            result.unwrap(),
            Some(TcpSessionState::Closing(TcpClosingState::AckFinSent))
        );
        {
            let s = tracker.sessions.get(&id).unwrap();
            assert_eq!(s.receiver.next_expected_seq, SeqNumber(5052), "receiver seq after server FIN");
        }

        // ── 9. Final ACK from client → TimeWait ──────────────────────────────
        // ack=5052 (server ISN + 1 data bytes + 1 for FIN).
        let result = tracker.process_tcp(make_packet(
                client(), server(), TcpFlags::ACK, 1102, 5052, 8192, 0,
        ));
        assert_eq!(result.unwrap(), Some(TcpSessionState::TimeWait));
        assert!(tracker.sessions.contains_key(&id), "session still present during TimeWait");
    }
}
