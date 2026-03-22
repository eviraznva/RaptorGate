use std::{marker::PhantomData, net::IpAddr, sync::Arc, time::{Duration, Instant}};

use bitflags::{bitflags, bitflags_match};
use dashmap::{DashMap, Entry};
use derive_more::{Add, AddAssign, Display, From, Into};
use etherparse::{TcpSlice, TransportSlice, err::tcp::HeaderSliceError};
use ngfw::frame::RealFrame;
use ringbuffer::{AllocRingBuffer, RingBuffer};
use thiserror::Error;
use unordered_pair::UnorderedPair;

use crate::frame::{Frame, Port};

pub struct TcpSessionTracker<T> {
    sessions: DashMap<TcpIdentifier, TcpSession>,
    buffer: Arc<PacketBuffer<T>>,
    marker: PhantomData<T>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, From, Add, AddAssign)]
struct AckNumber(u32);

impl AckNumber {
    fn wrapping_add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, From, Add, AddAssign)]
struct SeqNumber(u32);

impl SeqNumber {
    fn wrapping_add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs))
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
        let Some(flags) = TcpFlags::from_bits(tcp.header_slice()[TcpOffsets::FLAGS]) else { return Err(TcpSessionError::ZeroFlagPacket); /*FIXME: placeholder error*/ };
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

impl<T> TcpSessionTracker<T> where T: Frame + Send + Sync + 'static {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
            buffer: PacketBuffer::new(),
            marker: PhantomData,
        })
    }

    pub fn process_packet(&self, packet: TcpPacketInfo) -> Result<Option<TcpSessionState>, TcpSessionError> {
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

                match session.state {
                    TcpSessionState::Handshake(s) => match s {
                        TcpHandshakeState::SynSent => {
                            if packet.flags.contains(TcpFlags::SYN | TcpFlags::ACK)
                                && packet.src == session.receiver.id 
                                && packet.acknowledgment_number == session.initiator.next_expected_seq {
                                session.receiver.next_expected_seq = packet.sequence_number.wrapping_add(1);
                                session.receiver.max_window_size = packet.window_size;
                                session.state = TcpSessionState::Handshake(TcpHandshakeState::SynAckReceived);

                                self.process_from_buffer(TcpFlags::ACK, &id, &session.initiator.id)?;
                            }
                        },

                        TcpHandshakeState::SynAckReceived => {
                            if packet.flags.contains(TcpFlags::ACK)
                                && packet.src == session.initiator.id
                                && packet.sequence_number == session.initiator.next_expected_seq
                                && packet.acknowledgment_number == session.receiver.next_expected_seq {
                                session.state = TcpSessionState::Established;
                                session.initiator.next_expected_seq.wrapping_add(u32::from(packet.payload_size));
                            }
                        },

                    },
                    TcpSessionState::Established => todo!(),
                    TcpSessionState::Closed => todo!(),
                    TcpSessionState::ActiveTeardown => todo!(),
                    TcpSessionState::PassiveTeardown => todo!(),
                }

                Ok(Some(e.get().state))
            }

            Entry::Vacant(e) => {
                bitflags_match!(&packet.flags, {
                    &TcpFlags::SYN => { 
                        let inserted = e.insert(TcpSession { 
                            state: TcpSessionState::Handshake(TcpHandshakeState::SynSent),
                            initiator: Endpoint { id: packet.src.clone(), next_expected_seq: packet.sequence_number.wrapping_add(1), max_window_size: packet.window_size},
                            receiver: Endpoint { id: packet.dst.clone(), next_expected_seq: 0.into(), max_window_size: 0 },
                        });

                        self.process_from_buffer(TcpFlags::SYN | TcpFlags::ACK, inserted.key(), &packet.dst)?;

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

    fn process_from_buffer(&self, flags: TcpFlags, session_id: &TcpIdentifier, from: &EndpointIdentifier) -> Result<Option<TcpSessionState>, TcpSessionError> {
        let Some(packet) = self.buffer.get_session(session_id)
            .and_then(|s| s.iter()
                .find(|&p| p.flags == flags && &p.src == from).cloned())
            else { return Ok(None) };

        self.process_packet(packet)
    }
}
#[derive(Error, Debug)]
pub enum TcpSessionError {
    #[error("Packet with no flags")]
    ZeroFlagPacket,

    #[error("Buffer error: {0}")]
    BufferError(#[from] PacketBufferError),
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

struct PacketBuffer<T> {
    waiting: DashMap<TcpIdentifier, SessionPackets>,
    marker: PhantomData<T>,
}

impl<T> PacketBuffer<T> where T: Frame + Send + Sync + 'static {
    pub fn new() -> Arc<Self> {
        let buffer = Arc::new(Self {
            waiting: DashMap::new(),
            marker: PhantomData,
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
    struct TcpFlags: u8 {
        const SYN = 0b0001;
        const ACK = 0b0010;
        const RST = 0b0100;
        const FIN = 0b1000;
    }
}


const MAX_PENDING_PACKETS: usize = 4096;
const PENDING_TIMEOUT: Duration = Duration::from_millis(250);
const PENDING_PACKETS_PER_SESSION: usize = 16;


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
    pub const FLAGS: usize = 13;
}


struct TcpSession {
    state: TcpSessionState,
    initiator: Endpoint,
    receiver: Endpoint,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSessionState {
    Handshake(TcpHandshakeState),
    Established,
    Closed,
    ActiveTeardown,
    PassiveTeardown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHandshakeState {
    SynSent,
    SynAckReceived,
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
    use crate::frame::{Frame, Hour, IpGlobbable, IpVer, Octet, Port, Protocol, Weekday};
    use std::net::{IpAddr, Ipv4Addr};

    #[derive(Clone)]
    struct DummyFrame {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        ip_ver: IpVer,
        protocol: Protocol,
        src_port: Option<Port>,
        dst_port: Option<Port>,
        hour: Hour,
        day_of_week: Weekday,
    }

    impl Frame for DummyFrame {
        fn ip_ver(&self) -> IpVer {
            self.ip_ver
        }

        fn src_ip(&self) -> IpAddr {
            self.src_ip
        }

        fn dst_ip(&self) -> IpAddr {
            self.dst_ip
        }

        fn protocol(&self) -> Protocol {
            self.protocol
        }

        fn src_port(&self) -> Option<Port> {
            self.src_port
        }

        fn dst_port(&self) -> Option<Port> {
            self.dst_port
        }

        fn hour(&self) -> Hour {
            self.hour
        }

        fn day_of_week(&self) -> Weekday {
            self.day_of_week
        }

        fn transport_data(&'_ self) -> Option<&'_ etherparse::TransportSlice<'_>> {
            None
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

    fn mk_frame(i: usize) -> DummyFrame {
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

        DummyFrame {
            src_ip,
            dst_ip,
            ip_ver: IpVer::V4,
            protocol: Protocol::Tcp,
            src_port: Some(Port::from(12_345)),
            dst_port: Some(Port::from(443)),
            hour: Hour::try_from(12).expect("valid test hour"),
            day_of_week: Weekday::Mon,
        }
    }

    #[tokio::test]
    async fn establishes_new_session_on_first_packet() {
        let buffer = PacketBuffer::new();
        let id = mk_id(1);

        assert_eq!(buffer.waiting.len(), 0);
        let res = buffer.add_packet(id.clone(), mk_frame(1));
        assert!(res.is_ok());
        assert_eq!(buffer.waiting.len(), 1);
        assert!(buffer.waiting.contains_key(&id));
    }

    #[tokio::test]
    async fn cleans_up_sessions_after_timeout() {
        let buffer = PacketBuffer::new();
        let id = mk_id(2);

        buffer.add_packet(id.clone(), mk_frame(2)).unwrap();
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
            let res = buffer.add_packet(mk_id(i), mk_frame(i));
            assert!(res.is_ok(), "expected fill to succeed at {i}");
        }

        let overflow = buffer.add_packet(mk_id(max_sessions + 1), mk_frame(max_sessions + 1));
        match overflow {
            Err(PacketBufferError::BufferFull) => {}
            _ => panic!("expected PacketBufferError::BufferFull"),
        }
    }
}
