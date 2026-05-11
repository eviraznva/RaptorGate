pub mod udp;
pub mod tcp;
pub mod icmp;

use std::sync::Arc;
use thiserror::Error;
use etherparse::SlicedPacket;
use std::time::{Duration, Instant};

use crate::conntrack::config::ConntrackConfig;
use crate::conntrack::entry::{ConntrackEntry};
use crate::conntrack::proto::udp::UdpProtoState;
use crate::conntrack::proto::tcp::TcpProtoState;
use crate::conntrack::proto::icmp::IcmpProtoState;
use crate::conntrack::tuple::{Direction, FlowTuple, Protocol};

#[derive(Debug, Clone)]
pub enum ProtoState {
    Tcp(TcpProtoState),
    Udp(UdpProtoState),
    Icmp(IcmpProtoState),
}

/// Wynik `new_state()` — handler tworzy nowy stan flow albo deklaruje że pakiet jest RELATED do innego flow
#[derive(Debug, Clone)]
pub enum NewStateOutcome {
    State(ProtoState),
    Related { parent_tuple: FlowTuple },
}

impl From<ProtoState> for NewStateOutcome {
    fn from(s: ProtoState) -> Self { NewStateOutcome::State(s) }
}

#[derive(Debug, Error)]
pub enum NewStateError {
    #[error("packet too short for {proto:?} header")]
    TooShort { proto: Protocol },

    #[error("invalid first packet for {proto:?}: {reason}")]
    InvalidFirst { proto: Protocol, reason: &'static str },

    #[error("missing transport header")]
    MissingTransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtVerdict {
    Accept,  // Pakiet pasuje do flow
    Invalid, // Pakiet jest nieprawidłowy (np. złe flagi TCP, niekompletny nagłówek), ale go nie dropuje inna warstwa może zadecydować o jego losie
    Drop,    // Pakiet wymaga aby był zdropowany
}

pub trait ProtocolHandler: Send + Sync {
    fn proto(&self) -> Protocol;

    fn new_state(&self, pkt: &SlicedPacket, dir: Direction, config: &ConntrackConfig) -> Result<NewStateOutcome, NewStateError>;

    fn update(&self, entry: &ConntrackEntry, pkt: &SlicedPacket, dir: Direction, now: Instant, config: &ConntrackConfig) -> CtVerdict;

    fn timeout(&self, state: &ProtoState, config: &ConntrackConfig) -> Duration;

    fn is_assured(&self, _state: &ProtoState) -> bool { false }
}

pub struct ProtoRegistry {
    tcp: Option<Arc<dyn ProtocolHandler>>,
    udp: Option<Arc<dyn ProtocolHandler>>,
    icmp: Option<Arc<dyn ProtocolHandler>>,
    icmpv6: Option<Arc<dyn ProtocolHandler>>,
}

impl ProtoRegistry {
    pub fn new() -> Self {
        Self { tcp: None, udp: None, icmp: None, icmpv6: None }
    }

    pub fn register(&mut self, handler: Arc<dyn ProtocolHandler>) {
        match handler.proto() {
            Protocol::Tcp => self.tcp = Some(handler),
            Protocol::Udp => self.udp = Some(handler),
            Protocol::Icmp => self.icmp = Some(handler),
            Protocol::IcmpV6 => self.icmpv6 = Some(handler),
        }
    }

    pub fn get(&self, proto: Protocol) -> Option<&Arc<dyn ProtocolHandler>> {
        match proto {
            Protocol::Tcp => self.tcp.as_ref(),
            Protocol::Udp => self.udp.as_ref(),
            Protocol::Icmp => self.icmp.as_ref(),
            Protocol::IcmpV6 => self.icmpv6.as_ref(),
        }
    }
}

impl Default for ProtoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyHandler {
        proto: Protocol,
    }

    impl ProtocolHandler for DummyHandler {
        fn proto(&self) -> Protocol { self.proto }

        fn new_state(&self, _pkt: &SlicedPacket, _dir: Direction, _config: &ConntrackConfig) -> Result<NewStateOutcome, NewStateError> {
            Ok(NewStateOutcome::State(ProtoState::Udp(UdpProtoState::default())))
        }

        fn update(&self, _entry: &ConntrackEntry, _pkt: &SlicedPacket, _dir: Direction, _now: Instant, _config: &ConntrackConfig) -> CtVerdict {
            CtVerdict::Accept
        }

        fn timeout(&self, _state: &ProtoState, _config: &ConntrackConfig) -> Duration {
            Duration::from_secs(60)
        }
    }

    #[test]
    fn registry_dispatches_by_proto() {
        let mut registry = ProtoRegistry::new();
        registry.register(Arc::new(DummyHandler { proto: Protocol::Tcp }));
        registry.register(Arc::new(DummyHandler { proto: Protocol::Udp }));

        assert!(registry.get(Protocol::Tcp).is_some());
        assert!(registry.get(Protocol::Udp).is_some());
        assert!(registry.get(Protocol::Icmp).is_none());
    }

    #[test]
    fn registry_overwrites_on_double_register() {
        let mut registry = ProtoRegistry::new();
        registry.register(Arc::new(DummyHandler { proto: Protocol::Tcp }));

        let first = Arc::as_ptr(registry.get(Protocol::Tcp).unwrap());

        registry.register(Arc::new(DummyHandler { proto: Protocol::Tcp }));

        let second = Arc::as_ptr(registry.get(Protocol::Tcp).unwrap());

        assert_ne!(first, second);
    }

    #[test]
    fn default_is_assured_returns_false() {
        let h = DummyHandler { proto: Protocol::Udp };
        let state = ProtoState::Udp(UdpProtoState::default());

        assert!(!h.is_assured(&state));
    }

    fn _registry_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProtoRegistry>();
        assert_send_sync::<Arc<dyn ProtocolHandler>>();
    }
}