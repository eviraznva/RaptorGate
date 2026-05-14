use std::sync::Arc;

use crate::conntrack::entry::{ConntrackEntry, CtStatus};
use crate::conntrack::proto::ProtoState;

use super::reset::{TcpResetAction, TcpResetBuilder, TcpResetUnavailable};

fn apply_invalidation(entry: &ConntrackEntry, local: &mut bool) {
    if *local {
        return;
    }
    entry.set_status(CtStatus::DYING);
    *local = true;
}

pub struct TcpSessionContext {
    entry: Arc<ConntrackEntry>,
    local_invalidated: bool,
}

impl TcpSessionContext {
    pub fn new(entry: Arc<ConntrackEntry>) -> Self {
        Self {
            entry,
            local_invalidated: false,
        }
    }

    pub fn invalidate_session(&mut self) {
        apply_invalidation(&self.entry, &mut self.local_invalidated);
    }

    pub fn is_invalidated(&self) -> bool {
        self.local_invalidated || self.entry.has_status(CtStatus::DYING)
    }

    pub fn reset_session(&mut self) -> TcpResetAction {
        let tcp = {
            let guard = self.entry.proto_state.lock();
            match &*guard {
                ProtoState::Tcp(t) => t.clone(),
                _ => {
                    apply_invalidation(&self.entry, &mut self.local_invalidated);
                    return TcpResetAction::Unavailable {
                        reason: TcpResetUnavailable::NotTcpProtocol,
                    };
                }
            }
        };

        let action = TcpResetBuilder::from_entry(&self.entry, &tcp);
        apply_invalidation(&self.entry, &mut self.local_invalidated);
        action
    }
}

pub struct UdpSessionContext {
    entry: Arc<ConntrackEntry>,
    local_invalidated: bool,
}

impl UdpSessionContext {
    pub fn new(entry: Arc<ConntrackEntry>) -> Self {
        Self {
            entry,
            local_invalidated: false,
        }
    }

    pub fn invalidate_session(&mut self) {
        apply_invalidation(&self.entry, &mut self.local_invalidated);
    }

    pub fn is_invalidated(&self) -> bool {
        self.local_invalidated || self.entry.has_status(CtStatus::DYING)
    }
}

pub struct IcmpSessionContext {
    entry: Arc<ConntrackEntry>,
    local_invalidated: bool,
}

impl IcmpSessionContext {
    pub fn new(entry: Arc<ConntrackEntry>) -> Self {
        Self {
            entry,
            local_invalidated: false,
        }
    }

    pub fn invalidate_session(&mut self) {
        apply_invalidation(&self.entry, &mut self.local_invalidated);
    }

    pub fn is_invalidated(&self) -> bool {
        self.local_invalidated || self.entry.has_status(CtStatus::DYING)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::conntrack::proto::tcp::{TcpConntrack, TcpProtoState};
    use crate::conntrack::proto::udp::UdpProtoState;
    use crate::conntrack::tuple::{FlowTuple, Protocol};

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

    fn udp_entry() -> Arc<ConntrackEntry> {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            53,
            Protocol::Udp,
        );

        Arc::new(ConntrackEntry::new(
            8,
            tuple,
            ProtoState::Udp(UdpProtoState::default()),
            Duration::from_secs(30),
            0,
        ))
    }

    #[test]
    fn invalidate_marks_entry_dying_udp() {
        let entry = udp_entry();
        let mut ctx = UdpSessionContext::new(entry.clone());

        assert!(!ctx.is_invalidated());
        ctx.invalidate_session();
        assert!(ctx.is_invalidated());
        assert!(entry.has_status(CtStatus::DYING));
    }

    #[test]
    fn tcp_reset_on_handshake_returns_unavailable_and_invalidates() {
        let mut tcp = TcpProtoState::default();
        tcp.state = TcpConntrack::SynSent;
        tcp.seen[0].last_seq = 1;
        tcp.seen[1].last_seq = 2;

        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            Protocol::Tcp,
        );

        let entry = Arc::new(ConntrackEntry::new(
            9,
            tuple,
            ProtoState::Tcp(tcp),
            Duration::from_secs(60),
            0,
        ));

        let mut ctx = TcpSessionContext::new(entry.clone());
        let action = ctx.reset_session();

        assert!(matches!(
            action,
            TcpResetAction::Unavailable {
                reason: TcpResetUnavailable::HandshakeIncomplete
            }
        ));
        assert!(entry.has_status(CtStatus::DYING));
    }

    #[test]
    fn icmp_invalidate_marks_dying() {
        use crate::conntrack::proto::icmp::IcmpProtoState;

        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            0,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            0,
            Protocol::Icmp,
        );

        let entry = Arc::new(ConntrackEntry::new(
            10,
            tuple,
            ProtoState::Icmp(IcmpProtoState::default()),
            Duration::from_secs(30),
            0,
        ));

        let mut ctx = IcmpSessionContext::new(entry.clone());
        ctx.invalidate_session();
        assert!(entry.has_status(CtStatus::DYING));
    }

    #[test]
    fn tcp_reset_session_returns_pair_and_invalidates() {
        let entry = tcp_entry_established();
        let mut ctx = TcpSessionContext::new(entry.clone());

        let action = ctx.reset_session();

        let TcpResetAction::EmitRstPair { original, reply } = action else {
            panic!("expected EmitRstPair, got {action:?}");
        };

        assert_eq!(original.seq, 111);
        assert_eq!(original.ack, 222);
        assert_eq!(reply.seq, 333);
        assert_eq!(reply.ack, 444);
        assert!(ctx.is_invalidated());
        assert!(entry.has_status(CtStatus::DYING));
    }
}
