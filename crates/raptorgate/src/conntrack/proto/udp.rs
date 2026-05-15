use std::sync::Arc;
use std::time::{Duration, Instant};
use etherparse::{SlicedPacket, TransportSlice};


use crate::conntrack::config::ConntrackConfig;
use crate::conntrack::entry::{ConntrackEntry};
use crate::conntrack::observer::ObserverRegistry;
use crate::conntrack::tuple::{Direction, Protocol};
use crate::conntrack::proto::{CtVerdict, ProtocolHandler, NewStateError, NewStateOutcome, ProtoState};

#[derive(Debug, Clone, Default)]
pub struct UdpProtoState {
    pub stream: bool,
    pub packets_orig: u32,
    pub packets_reply: u32,
}

pub struct UdpHandler {
    observers: Arc<ObserverRegistry>,
}

impl UdpHandler {
    pub fn new(observers: Arc<ObserverRegistry>) -> Self {
        Self { observers }
    }
}

impl ProtocolHandler for UdpHandler {
    fn proto(&self) -> Protocol {
        Protocol::Udp
    }

    fn new_state(&self, pkt: &SlicedPacket, _dir: Direction, _config: &ConntrackConfig) -> Result<NewStateOutcome, NewStateError> {
        let TransportSlice::Udp(_) = pkt.transport.as_ref().ok_or(NewStateError::MissingTransport)?
            else {
                return Err(NewStateError::InvalidFirst {
                    proto: Protocol::Udp,
                    reason: "transport is not UDP",
                });
            };

        Ok(NewStateOutcome::State(ProtoState::Udp(UdpProtoState {
            stream: false,
            packets_orig: 1,
            packets_reply: 0,
        })))
    }

    fn update(
        &self,
        entry: &ConntrackEntry,
        pkt: &SlicedPacket,
        dir: Direction,
        _now: Instant,
        _config: &ConntrackConfig,
        packet_id: crate::data_plane::packet_context::PacketId,
    ) -> CtVerdict {
        let Some(TransportSlice::Udp(udp)) = pkt.transport.as_ref() else {
            return CtVerdict::Invalid;
        };

        let mut state_guard = entry.proto_state.lock();

        let ProtoState::Udp(state) = &mut *state_guard else {
            return CtVerdict::Invalid;
        };

        match dir {
            Direction::Original => state.packets_orig = state.packets_orig.saturating_add(1),
            Direction::Reply => {
                state.packets_reply = state.packets_reply.saturating_add(1);
                state.stream = true;
            },
        }

        let payload = udp.payload();
        
        if !payload.is_empty() {
            self.observers.fire_payload(
                entry,
                dir,
                &crate::conntrack::reassembler::DeliveredChunk {
                    packet_id,
                    payload: payload.to_vec(),
                    tcp_payload_start_seq: 0,
                },
            );
        }

        CtVerdict::Accept
    }

    fn timeout(&self, state: &ProtoState, config: &ConntrackConfig) -> Duration {
        let ProtoState::Udp(udp) = state else {
            return config.udp.timeout;
        };

        if udp.stream {
            config.udp.stream_timeout
        } else {
            config.udp.timeout
        }
    }

    fn is_assured(&self, state: &ProtoState) -> bool {
        let ProtoState::Udp(udp) = state else {
            return false;
        };

        udp.stream && udp.packets_orig >= 2 && udp.packets_reply >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_plane::packet_context::PacketId;
    use etherparse::PacketBuilder;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::conntrack::tuple::FlowTuple;

    fn build_udp(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        let payload = [0u8; 4];

        let builder = PacketBuilder::ipv4(src_ip, dst_ip, 64).udp(src_port, dst_port);
        let mut buf = Vec::with_capacity(builder.size(payload.len()));

        builder.write(&mut buf, &payload).unwrap();

        buf
    }

    fn slice(buf: &[u8]) -> SlicedPacket<'_> {
        SlicedPacket::from_ip(buf).unwrap()
    }

    fn entry_for(state: UdpProtoState) -> ConntrackEntry {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            53000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            Protocol::Udp,
        );

        ConntrackEntry::new(
            1,
            tuple,
            ProtoState::Udp(state),
            Duration::from_secs(30),
            0,
        )
    }

    #[test]
    fn new_state_initializes_with_one_orig_packet() {
        let buf = build_udp([10, 0, 0, 1], 53000, [8, 8, 8, 8], 53);

        let pkt = slice(&buf);

        let h = UdpHandler::new(Arc::new(ObserverRegistry::default()));
        let cfg = ConntrackConfig::default();

        let outcome = h.new_state(&pkt, Direction::Original, &cfg).unwrap();

        let NewStateOutcome::State(ProtoState::Udp(udp)) = outcome else { panic!("wrong variant"); };

        assert_eq!(udp.packets_orig, 1);
        assert_eq!(udp.packets_reply, 0);
        assert!(!udp.stream);
    }

    #[test]
    fn update_reply_sets_stream() {
        let buf = build_udp([8, 8, 8, 8], 53, [10, 0, 0, 1], 53000);

        let pkt = slice(&buf);

        let entry = entry_for(UdpProtoState { stream: false, packets_orig: 1, packets_reply: 0 });

        let h = UdpHandler::new(Arc::new(ObserverRegistry::default()));

        let verdict = h.update(&entry, &pkt, Direction::Reply, Instant::now(), &ConntrackConfig::default(), PacketId(0));

        assert_eq!(verdict, CtVerdict::Accept);

        let guard = entry.proto_state.lock();

        let ProtoState::Udp(s) = &*guard else { panic!(); };

        assert!(s.stream);
        assert_eq!(s.packets_reply, 1);
    }

    #[test]
    fn timeout_reflects_stream_state() {
        let h = UdpHandler::new(Arc::new(ObserverRegistry::default()));
        let cfg = ConntrackConfig::default();

        let unreplied = ProtoState::Udp(UdpProtoState::default());
        assert_eq!(h.timeout(&unreplied, &cfg), Duration::from_secs(30));

        let replied = ProtoState::Udp(UdpProtoState {
            stream: true,
            packets_orig: 5,
            packets_reply: 5,
        });

        assert_eq!(h.timeout(&replied, &cfg), Duration::from_secs(120));
    }

    #[test]
    fn is_assured_requires_two_each_direction_and_stream() {
        let h = UdpHandler::new(Arc::new(ObserverRegistry::default()));

        let cases = [
            (UdpProtoState { stream: false, packets_orig: 5, packets_reply: 5 }, false),
            (UdpProtoState { stream: true, packets_orig: 1, packets_reply: 5 }, false),
            (UdpProtoState { stream: true, packets_orig: 5, packets_reply: 1 }, false),
            (UdpProtoState { stream: true, packets_orig: 2, packets_reply: 2 }, true),
            (UdpProtoState { stream: true, packets_orig: 100, packets_reply: 100 }, true),
        ];

        for (state, expected) in cases {
            assert_eq!(h.is_assured(&ProtoState::Udp(state.clone())), expected, "state: {:?}", state);
        }
    }

    #[test]
    fn update_with_non_udp_packet_returns_invalid() {
        let payload = [0u8; 4];

        let builder = PacketBuilder::ipv4([10, 0, 0, 1], [8, 8, 8, 8], 64)
            .tcp(1000, 80, 1, 5840);

        let mut buf = Vec::with_capacity(builder.size(payload.len()));

        builder.write(&mut buf, &payload).unwrap();

        let pkt = slice(&buf);

        let entry = entry_for(UdpProtoState::default());
        let h = UdpHandler::new(Arc::new(ObserverRegistry::default()));

        assert_eq!(
            h.update(&entry, &pkt, Direction::Original, Instant::now(), &ConntrackConfig::default(), PacketId(0)),
            CtVerdict::Invalid
        );
    }
}