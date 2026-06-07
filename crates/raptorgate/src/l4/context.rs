use std::sync::Arc;
use std::time::SystemTime;

use crate::conntrack::entry::ConntrackEntry;
use crate::conntrack::tcp_identity::EndpointIdentifier;
use crate::conntrack::tuple::Direction;
use crate::dpi::AppProto;
use crate::events::{Event, EventKind, emit};
use crate::l4::reset::{TcpResetAction, TcpResetBuilder, TcpResetUnavailable};
use crate::proto::events::DecidedAppProtocol;
use crate::zones::resolver::ZoneResolver;
use crate::zones::{DirectionalZonePairs, ResolvedZonePair};

#[derive(Debug)]
pub struct SessionContext {
    entry: Arc<ConntrackEntry>,
    application_protocol: Option<AppProto>,
    zone_pair_in_to_out: ResolvedZonePair,
    zone_pair_out_to_in: ResolvedZonePair,
}

impl SessionContext {
    pub fn open(entry: Arc<ConntrackEntry>, zone_resolver: &impl ZoneResolver) -> Self {
        let pairs = zone_resolver.resolve_bidirectional(entry.original.src_ip, entry.original.dst_ip);
        let (zone_pair_in_to_out, zone_pair_out_to_in) = zone_pairs_from_directional(pairs);
        Self {
            entry,
            application_protocol: None,
            zone_pair_in_to_out,
            zone_pair_out_to_in,
        }
    }

    pub fn entry(&self) -> &Arc<ConntrackEntry> {
        &self.entry
    }

    pub fn application_protocol(&self) -> Option<AppProto> {
        self.application_protocol
    }

    pub fn set_application_protocol(&mut self, app_proto: AppProto) {
        emit(Event {
            emitted_at: SystemTime::now(),
            kind: EventKind::DecidedAppProtocol {
                protocol: app_proto,
                zone_pair_in_to_out: self.zone_pair_in_to_out.clone(),
                zone_pair_out_to_in: self.zone_pair_out_to_in.clone(),
            },
        });
        self.application_protocol = Some(app_proto);
    }

    pub fn zone_pair_for_packet(&self, dir: Direction) -> &ResolvedZonePair {
        match dir {
            Direction::Original => &self.zone_pair_in_to_out,
            Direction::Reply => &self.zone_pair_out_to_in,
        }
    }

    pub fn endpoints(&self, dir: Direction) -> (EndpointIdentifier, EndpointIdentifier) {
        let t = match dir {
            Direction::Original => self.entry.original,
            Direction::Reply => self.entry.reply(),
        };
        (
            EndpointIdentifier {
                ip: t.src_ip,
                port: t.src_port.into(),
            },
            EndpointIdentifier {
                ip: t.dst_ip,
                port: t.dst_port.into(),
            },
        )
    }

    pub fn build_tcp_reset(&self) -> TcpResetAction {
        let tcp = {
            let guard = self.entry.proto_state.lock();
            match &*guard {
                crate::conntrack::proto::ProtoState::Tcp(t) => t.clone(),
                _ => {
                    return TcpResetAction::Unavailable {
                        reason: TcpResetUnavailable::NotTcpProtocol,
                    };
                }
            }
        };
        TcpResetBuilder::from_entry(&self.entry, &tcp)
    }
}

fn zone_pairs_from_directional(pairs: DirectionalZonePairs) -> (ResolvedZonePair, ResolvedZonePair) {
    let fallback = ResolvedZonePair {
        id: uuid::Uuid::nil().into(),
        default_policy: crate::zones::DefaultPolicy::Allow,
    };
    (
        pairs.forward.unwrap_or_else(|| fallback.clone()),
        pairs.reverse.unwrap_or(fallback),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::conntrack::proto::tcp::{TcpConntrack, TcpProtoState};
    use crate::conntrack::proto::ProtoState;
    use crate::conntrack::tuple::{FlowTuple, Protocol};
    use crate::zones::resolver::ZoneResolver;
    use crate::zones::{ResolvedZonePair, ZonePairId};

    struct StubZoneResolver;

    impl ZoneResolver for StubZoneResolver {
        fn resolve(&self, _src_interface_name: &str, _dst_ip: IpAddr) -> Option<ResolvedZonePair> {
            Some(ResolvedZonePair {
                id: ZonePairId::from(uuid::Uuid::nil()),
                default_policy: crate::zones::DefaultPolicy::Allow,
            })
        }

        fn resolve_bidirectional(&self, _src_ip: IpAddr, _dst_ip: IpAddr) -> DirectionalZonePairs {
            let pair = ResolvedZonePair {
                id: ZonePairId::from(uuid::Uuid::nil()),
                default_policy: crate::zones::DefaultPolicy::Allow,
            };
            DirectionalZonePairs {
                forward: Some(pair.clone()),
                reverse: Some(pair),
            }
        }
    }

    fn tcp_entry_established() -> Arc<ConntrackEntry> {
        let mut tcp = TcpProtoState::default();
        tcp.state = TcpConntrack::Established;
        tcp.seen[0].last_seq = 111;
        tcp.seen[0].last_ack = 222;
        tcp.seen[1].last_seq = 333;
        tcp.seen[1].last_ack = 444;

        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            Protocol::Tcp,
        );

        Arc::new(ConntrackEntry::new(
            7,
            tuple,
            ProtoState::Tcp(tcp),
            Duration::from_secs(60),
            1,
        ))
    }

    #[test]
    fn tcp_reset_session_returns_pair() {
        let entry = tcp_entry_established();
        let ctx = SessionContext::open(entry, &StubZoneResolver);

        let TcpResetAction::EmitRstPair { original, reply } = ctx.build_tcp_reset() else {
            panic!("expected EmitRstPair");
        };

        assert_eq!(original.seq, 111);
        assert_eq!(original.ack, 222);
        assert_eq!(reply.seq, 333);
        assert_eq!(reply.ack, 444);
    }
}
