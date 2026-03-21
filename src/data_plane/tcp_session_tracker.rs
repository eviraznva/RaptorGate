use std::{net::IpAddr, sync::Arc, time::{Duration, Instant}};

use dashmap::{DashMap, Entry};
use derive_more::{Display, Error};
use ngfw::frame::RealFrame;
use ringbuffer::{AllocRingBuffer, RingBuffer};
use unordered_pair::UnorderedPair;

use crate::frame::{Frame, Port};

pub struct TcpSessionTracker<T> {
    sessions: DashMap<TcpIdentifier, TcpSessionState>,
    buffer: Arc<PacketBuffer<T>>,
}

impl<T> TcpSessionTracker<T> where T: Frame + Send + Sync + 'static {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
            buffer: PacketBuffer::new(),
        })
    }

    pub fn process_packet(&self, frame: T) {
        let id = TcpIdentifier {
            endpoints: UnorderedPair::from(
               (Endpoint {
                   ip: frame.src_ip().into(),
                   port: frame.src_port().unwrap_or(Port::from(0)),
               },
               Endpoint {
                   ip: frame.dst_ip().into(),
                   port: frame.dst_port().unwrap_or(Port::from(0)),
               })
           )
        };
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct TcpIdentifier {
    endpoints: UnorderedPair<Endpoint>
}


#[derive(Clone, Hash, PartialEq, Eq, Ord, PartialOrd)]
struct Endpoint {
    ip: IpAddr,
    port: Port,
}

struct PacketBuffer<T> {
    waiting: DashMap<TcpIdentifier, SessionPackets<T>>
}

const MAX_PENDING_PACKETS: usize = 4096;
const PENDING_TIMEOUT: Duration = Duration::from_millis(250);
const PENDING_PACKETS_PER_SESSION: usize = 16;

impl<T> PacketBuffer<T> where T: Frame + Send + Sync + 'static {
    pub fn new() -> Arc<Self> {
        let buffer = Arc::new(Self {
            waiting: DashMap::new(),
        });

        let sweeper = Arc::clone(&buffer);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PENDING_TIMEOUT);
            loop {
                interval.tick().await;
                sweeper.sweep();
            }
        });

        buffer
    }

    fn sweep(&self) {
        self.waiting.retain(|_, v| {
            v.first_packet_arrival.elapsed() < PENDING_TIMEOUT
        });
    }

    fn add_packet(&self, id: TcpIdentifier, frame: T) -> Result<(), PacketBufferError>  {
        // we preallocate the buffers for each session so we can perform a simple check like this
        let is_full = self.waiting.len() * PENDING_PACKETS_PER_SESSION >= MAX_PENDING_PACKETS;

        match self.waiting.entry(id) {
            Entry::Occupied(mut occupied) => {
                if occupied.get().first_packet_arrival.elapsed() > PENDING_TIMEOUT {
                    occupied.remove_entry();
                    return Err(PacketBufferError::SessionExpired);
                }
                occupied.get_mut().packets.enqueue(frame);
                Ok(())
            }

            Entry::Vacant(vacant) => {
                if is_full {
                    return Err(PacketBufferError::BufferFull);
                }

                let mut session_packets = SessionPackets::new(Instant::now());
                session_packets.packets.enqueue(frame);
                vacant.insert(session_packets);
                Ok(())
            }
        }
    }
}

struct SessionPackets<T> {
    // TODO: store only l3+ info here instead of l2
    packets: AllocRingBuffer<T>,
    first_packet_arrival: Instant,
}

impl<T> SessionPackets<T> where T: Frame {
    fn new(arrival_time: Instant) -> Self {
        Self {
            packets: AllocRingBuffer::new(PENDING_PACKETS_PER_SESSION),
            first_packet_arrival: arrival_time,
        }
    }
}

struct TcpSession {
    start_time: Instant,
    state: TcpSessionState,
}

enum TcpSessionState {
    Established,
    Closed,
}

#[derive(Error, Debug, Display)]
pub enum PacketBufferError {
    #[display("TCP session expired")]
    SessionExpired,
    #[display("Packet buffer full")]
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
    }

    fn mk_id(i: usize) -> TcpIdentifier {
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let src_port = Port::from((10_000 + (i % 50_000)) as u16);
        let dst_port = Port::from(443);

        TcpIdentifier {
            endpoints: UnorderedPair::from((
                Endpoint { ip: src_ip, port: src_port },
                Endpoint { ip: dst_ip, port: dst_port },
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
