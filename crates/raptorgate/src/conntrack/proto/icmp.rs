use std::time::{Duration, Instant};
use etherparse::{Icmpv4Type, Icmpv6Type, SlicedPacket, TransportSlice};

use crate::conntrack::entry::{ConntrackEntry};
use crate::conntrack::config::ConntrackConfig;
use crate::conntrack::tuple::{Direction, FlowTuple, Protocol};
use crate::conntrack::proto::{CtVerdict, ProtocolHandler, NewStateError, NewStateOutcome, ProtoState};

#[derive(Debug, Clone, Default)]
pub struct IcmpProtoState {
    pub kind: IcmpKind,
    pub seen_reply: bool,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IcmpKind {
    #[default]
    Echo,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IcmpClass {
    Request,       // Tworzy nowy flow
    Reply,         // Pasuje do istniejącego flow jako reply
    Error,         // Niesie embedded packet, RELATED do parent
    Unsupported,   // Nie śledzimy
}

fn classify_v4(t: Icmpv4Type) -> IcmpClass {
    use Icmpv4Type::*;

    match t {
        EchoRequest(_)              => IcmpClass::Request,
        EchoReply(_)                => IcmpClass::Reply,
        TimestampRequest(_)         => IcmpClass::Request,
        TimestampReply(_)           => IcmpClass::Reply,
        DestinationUnreachable(_)
        | TimeExceeded(_)
        | ParameterProblem(_)
        | Redirect(_)               => IcmpClass::Error,
        _                           => IcmpClass::Unsupported,
    }
}

fn classify_v6(t: Icmpv6Type) -> IcmpClass {
    use Icmpv6Type::*;
    
    match t {
        EchoRequest(_)              => IcmpClass::Request,
        EchoReply(_)                => IcmpClass::Reply,
        DestinationUnreachable(_)
        | PacketTooBig { .. }
        | TimeExceeded(_)
        | ParameterProblem(_)       => IcmpClass::Error,
        _                           => IcmpClass::Unsupported,
    }
}

pub struct IcmpHandler {
    is_v6: bool,
}

impl IcmpHandler {
    pub fn v4() -> Self { Self { is_v6: false } }

    pub fn v6() -> Self { Self { is_v6: true } }

    fn classify_packet(&self, pkt: &SlicedPacket) -> Result<IcmpClass, NewStateError> {
        let transport = pkt.transport.as_ref().ok_or(NewStateError::MissingTransport)?;

        match (self.is_v6, transport) {
            (false, TransportSlice::Icmpv4(icmp)) => {
                Ok(classify_v4(icmp.icmp_type()))
            },
            
            (true, TransportSlice::Icmpv6(icmp)) => {
                Ok(classify_v6(icmp.icmp_type()))
            },
            
            _ => Err(NewStateError::InvalidFirst {
                proto: self.proto(),
                reason: "transport family mismatch",
            }),
        }
    }

    /// Parsuje embedded packet z payloadu ICMP error i buduje `FlowTuple` odpowiadający parent flow
    fn parse_embedded_inner_tuple(pkt: &SlicedPacket) -> Option<FlowTuple> {
        let payload = match pkt.transport.as_ref()? {
            TransportSlice::Icmpv4(icmp) => icmp.payload(),
            TransportSlice::Icmpv6(icmp) => icmp.payload(),
            _ => return None,
        };

        let inner = SlicedPacket::from_ip(payload).ok()?;

        FlowTuple::from_sliced(&inner)
    }
}

impl ProtocolHandler for IcmpHandler {
    fn proto(&self) -> Protocol {
        if self.is_v6 { Protocol::IcmpV6 } else { Protocol::Icmp }
    }

    fn new_state(&self, pkt: &SlicedPacket, _dir: Direction, _config: &ConntrackConfig) -> Result<NewStateOutcome, NewStateError> {
        let class = self.classify_packet(pkt)?;

        match class {
            IcmpClass::Request => Ok(NewStateOutcome::State(ProtoState::Icmp(IcmpProtoState {
                kind: IcmpKind::Echo,
                seen_reply: false,
                count: 1,
            }))),

            IcmpClass::Reply => Err(NewStateError::InvalidFirst {
                proto: self.proto(),
                reason: "first packet is reply, no parent flow",
            }),

            IcmpClass::Error => {
                let parent = Self::parse_embedded_inner_tuple(pkt)
                    .ok_or(NewStateError::InvalidFirst {
                        proto: self.proto(),
                        reason: "ICMP error without parseable embedded packet",
                    })?;

                Ok(NewStateOutcome::Related { parent_tuple: parent })
            },

            IcmpClass::Unsupported => Err(NewStateError::InvalidFirst {
                proto: self.proto(),
                reason: "unsupported ICMP type",
            }),
        }
    }

    fn update(
        &self,
        entry: &ConntrackEntry,
        pkt: &SlicedPacket,
        dir: Direction,
        _now: Instant,
        _config: &ConntrackConfig,
        _packet_id: crate::data_plane::packet_context::PacketId,
    ) -> CtVerdict {
        let Ok(class) = self.classify_packet(pkt) else {
            return CtVerdict::Invalid;
        };

        let mut state_guard = entry.proto_state.lock();

        let ProtoState::Icmp(state) = &mut *state_guard else {
            return CtVerdict::Invalid;
        };

        match (class, dir) {
            (IcmpClass::Request, Direction::Original) | (IcmpClass::Reply, Direction::Reply) => {
                state.count = state.count.saturating_add(1);

                if class == IcmpClass::Reply {
                    state.seen_reply = true;
                }

                CtVerdict::Accept
            },

            (IcmpClass::Request, Direction::Reply) | (IcmpClass::Reply, Direction::Original) => CtVerdict::Invalid,

            (IcmpClass::Error, _) => {
                state.count = state.count.saturating_add(1);

                CtVerdict::Accept
            },

            (IcmpClass::Unsupported, _) => CtVerdict::Invalid,
        }
    }

    fn timeout(&self, _state: &ProtoState, config: &ConntrackConfig) -> Duration {
        config.icmp.timeout
    }

    fn is_assured(&self, state: &ProtoState) -> bool {
        let ProtoState::Icmp(icmp) = state else { return false; };

        icmp.seen_reply && icmp.count >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_plane::packet_context::PacketId;
    use etherparse::{PacketBuilder};
    use std::net::{IpAddr, Ipv4Addr};
    use crate::conntrack::tuple::FlowTuple;

    fn build_echo_request(id: u16, seq: u16) -> Vec<u8> {
        let payload = b"hello";
        
        let builder = PacketBuilder::ipv4([10, 0, 0, 1], [8, 8, 8, 8], 64)
            .icmpv4_echo_request(id, seq);
        
        let mut buf = Vec::with_capacity(builder.size(payload.len()));
        
        builder.write(&mut buf, payload).unwrap();
        
        buf
    }

    fn build_echo_reply(id: u16, seq: u16) -> Vec<u8> {
        let payload = b"hello";
        
        let builder = PacketBuilder::ipv4([8, 8, 8, 8], [10, 0, 0, 1], 64)
            .icmpv4_echo_reply(id, seq);
        
        let mut buf = Vec::with_capacity(builder.size(payload.len()));
        
        builder.write(&mut buf, payload).unwrap();
        
        buf
    }

    fn slice(buf: &[u8]) -> SlicedPacket<'_> {
        SlicedPacket::from_ip(buf).unwrap()
    }

    fn fresh_entry() -> ConntrackEntry {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            42,                                            // id
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            0,
            Protocol::Icmp,
        );
        
        ConntrackEntry::new(
            1,
            tuple,
            ProtoState::Icmp(IcmpProtoState {
                kind: IcmpKind::Echo,
                seen_reply: false,
                count: 1,
            }),
            Duration::from_secs(30),
            0,
        )
    }

    #[test]
    fn new_state_accepts_echo_request() {
        let buf = build_echo_request(42, 1);
        
        let pkt = slice(&buf);
        
        let h = IcmpHandler::v4();
        
        let outcome = h.new_state(&pkt, Direction::Original, &ConntrackConfig::default()).unwrap();

        let NewStateOutcome::State(ProtoState::Icmp(icmp)) = outcome else { panic!(); };
        
        assert_eq!(icmp.count, 1);
        assert!(!icmp.seen_reply);
    }

    #[test]
    fn new_state_rejects_echo_reply() {
        let buf = build_echo_reply(42, 1);
        
        let pkt = slice(&buf);
        
        let h = IcmpHandler::v4();
        
        assert!(matches!(
              h.new_state(&pkt, Direction::Original, &ConntrackConfig::default()),
              Err(NewStateError::InvalidFirst { .. })
          ));
    }

    #[test]
    fn update_reply_in_reply_direction_sets_seen() {
        let buf = build_echo_reply(42, 1);
        
        let pkt = slice(&buf);
        
        let entry = fresh_entry();
        
        let h = IcmpHandler::v4();

        let v = h.update(&entry, &pkt, Direction::Reply, Instant::now(), &ConntrackConfig::default(), PacketId(0));

        assert_eq!(v, CtVerdict::Accept);
        
        let g = entry.proto_state.lock();
        
        let ProtoState::Icmp(s) = &*g else { panic!(); };
        
        assert!(s.seen_reply);
        assert_eq!(s.count, 2);
    }

    #[test]
    fn update_reply_in_original_direction_invalid() {
        let buf = build_echo_reply(42, 1);
        
        let pkt = slice(&buf);
        
        let entry = fresh_entry();
        
        let h = IcmpHandler::v4();

        let v = h.update(&entry, &pkt, Direction::Original, Instant::now(), &ConntrackConfig::default(), PacketId(0));

        assert_eq!(v, CtVerdict::Invalid);
    }

    #[test]
    fn timeout_uses_config() {
        let h = IcmpHandler::v4();
        
        let cfg = ConntrackConfig::default();
        
        let state = ProtoState::Icmp(IcmpProtoState::default());
        
        assert_eq!(h.timeout(&state, &cfg), Duration::from_secs(30));
    }

    #[test]
    fn is_assured_requires_reply_and_two_packets() {
        let h = IcmpHandler::v4();
        
        let cases = [
            (IcmpProtoState { kind: IcmpKind::Echo, seen_reply: false, count: 5 }, false),
            (IcmpProtoState { kind: IcmpKind::Echo, seen_reply: true, count: 1 }, false),
            (IcmpProtoState { kind: IcmpKind::Echo, seen_reply: true, count: 2 }, true),
        ];
        
        for (state, expected) in cases {
            let s = state.clone();
            assert_eq!(h.is_assured(&ProtoState::Icmp(state)), expected, "state: {:?}", s);
        }
    }

    #[test]
    fn proto_dispatches_by_family() {
        assert_eq!(IcmpHandler::v4().proto(), Protocol::Icmp);
        assert_eq!(IcmpHandler::v6().proto(), Protocol::IcmpV6);
    }
}