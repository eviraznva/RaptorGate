use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

use crate::conntrack::entry::ConntrackEntry;
use crate::conntrack::observer::{CtObserver, DestroyReason};
use crate::conntrack::proto::ProtoState;
use crate::conntrack::table::Conntrack;
use crate::conntrack::tuple::{Direction, FlowTuple};
use crate::data_plane::packet_context::PacketContext;
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage};
use crate::l4::{
    IcmpL4PipelineFactory, IcmpNoopPipeline, TcpL4PipelineFactory, TcpNoopPipeline, UdpL4PipelineFactory, UdpNoopPipeline,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub entry_id: u64,
    pub original: FlowTuple,
}

pub fn flow_key_for(entry: &ConntrackEntry) -> FlowKey {
    FlowKey {
        entry_id: entry.id,
        original: entry.original,
    }
}

pub struct L4Input {
    pub packet: PacketContext,
    pub dir: Direction,
    pub entry: Arc<ConntrackEntry>,
}

#[derive(Debug, Error)]
pub enum SessionSendError {
    #[error("session task disconnected")]
    Disconnected,
}

#[derive(Clone)]
pub struct SessionHandle {
    tx: mpsc::UnboundedSender<L4Input>,
}

impl SessionHandle {
    pub fn send(&self, input: L4Input) -> Result<(), SessionSendError> {
        self.tx.send(input).map_err(|_| SessionSendError::Disconnected)
    }
}

enum Phase1NoopPipeline {
    Tcp(TcpNoopPipeline),
    Udp(UdpNoopPipeline),
    Icmp(IcmpNoopPipeline),
}

impl Phase1NoopPipeline {
    fn from_proto(
        proto: &ProtoState,
        tcp_f: TcpL4PipelineFactory,
        udp_f: UdpL4PipelineFactory,
        icmp_f: IcmpL4PipelineFactory,
    ) -> Self {
        match proto {
            ProtoState::Tcp(_) => Self::Tcp(tcp_f.build()),
            ProtoState::Udp(_) => Self::Udp(udp_f.build()),
            ProtoState::Icmp(_) => Self::Icmp(icmp_f.build()),
        }
    }

    fn on_session_open(&mut self, ctx: &mut ()) -> L4Outcome {
        match self {
            Self::Tcp(p) => p.on_session_open(ctx),
            Self::Udp(p) => p.on_session_open(ctx),
            Self::Icmp(p) => p.on_session_open(ctx),
        }
    }

    fn on_packet(&mut self, ctx: &mut (), packet: &mut PacketContext, dir: Direction) -> L4Outcome {
        match self {
            Self::Tcp(p) => p.on_packet(ctx, packet, dir),
            Self::Udp(p) => p.on_packet(ctx, packet, dir),
            Self::Icmp(p) => p.on_packet(ctx, packet, dir),
        }
    }

    fn on_session_close(&mut self, ctx: &mut (), reason: CloseReason) -> L4Outcome {
        match self {
            Self::Tcp(p) => p.on_session_close(ctx, reason),
            Self::Udp(p) => p.on_session_close(ctx, reason),
            Self::Icmp(p) => p.on_session_close(ctx, reason),
        }
    }
}

pub struct SessionManager {
    ct: Arc<Conntrack>,
    tcp_factory: TcpL4PipelineFactory,
    udp_factory: UdpL4PipelineFactory,
    icmp_factory: IcmpL4PipelineFactory,
    handles: DashMap<FlowKey, SessionHandle>,
    trace: Option<Arc<Mutex<Vec<String>>>>,
    observer_events: AtomicUsize,
}

impl SessionManager {
    pub fn new(
        ct: Arc<Conntrack>,
        tcp_factory: TcpL4PipelineFactory,
        udp_factory: UdpL4PipelineFactory,
        icmp_factory: IcmpL4PipelineFactory,
    ) -> Arc<Self> {
        Arc::new(Self {
            ct,
            tcp_factory,
            udp_factory,
            icmp_factory,
            handles: DashMap::new(),
            trace: None,
            observer_events: AtomicUsize::new(0),
        })
    }

    pub fn new_with_event_trace(
        ct: Arc<Conntrack>,
        tcp_factory: TcpL4PipelineFactory,
        udp_factory: UdpL4PipelineFactory,
        icmp_factory: IcmpL4PipelineFactory,
        trace: Arc<Mutex<Vec<String>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ct,
            tcp_factory,
            udp_factory,
            icmp_factory,
            handles: DashMap::new(),
            trace: Some(trace),
            observer_events: AtomicUsize::new(0),
        })
    }

    pub fn conntrack(&self) -> &Arc<Conntrack> {
        &self.ct
    }

    pub fn active_sessions(&self) -> usize {
        self.handles.len()
    }

    pub fn handle_for_entry(self: &Arc<Self>, entry: &Arc<ConntrackEntry>) -> SessionHandle {
        let key = flow_key_for(entry);
        self.handles
            .entry(key)
            .or_insert_with(|| Self::spawn_session_task(self.clone(), entry.clone()))
            .clone()
    }

    fn spawn_session_task(sm: Arc<SessionManager>, entry: Arc<ConntrackEntry>) -> SessionHandle {
        let (tx, mut rx) = mpsc::unbounded_channel::<L4Input>();
        let trace = sm.trace.clone();
        let tcp_f = sm.tcp_factory;
        let udp_f = sm.udp_factory;
        let icmp_f = sm.icmp_factory;

        tokio::spawn(async move {
            let proto = { entry.proto_state.lock().clone() };
            let mut pipeline = Phase1NoopPipeline::from_proto(&proto, tcp_f, udp_f, icmp_f);
            let mut ctx = ();

            if let Some(t) = &trace {
                t.lock().await.push("open".to_string());
            }
            let _ = pipeline.on_session_open(&mut ctx);

            while let Some(mut input) = rx.recv().await {
                if let Some(t) = &trace {
                    t.lock().await.push("packet".to_string());
                }
                let _ = pipeline.on_packet(&mut ctx, &mut input.packet, input.dir);
            }

            if let Some(t) = &trace {
                t.lock().await.push("close".to_string());
            }
            let _ = pipeline.on_session_close(&mut ctx, CloseReason::Finished);
        });

        SessionHandle { tx }
    }

    pub fn observer_event_count(&self) -> usize {
        self.observer_events.load(Ordering::Relaxed)
    }
}

impl CtObserver for SessionManager {
    fn on_new(&self, entry: &ConntrackEntry) {
        self.observer_events.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(event = "session_manager.on_new", entry_id = entry.id, "conntrack new entry");
    }

    fn on_payload(&self, entry: &ConntrackEntry, dir: Direction, payload: &[u8]) {
        self.observer_events.fetch_add(1, Ordering::Relaxed);
        tracing::trace!(
            event = "session_manager.on_payload",
            entry_id = entry.id,
            dir = ?dir,
            len = payload.len(),
            "conntrack payload"
        );
    }

    fn on_destroy(&self, entry: &ConntrackEntry, reason: DestroyReason) {
        self.observer_events.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            event = "session_manager.on_destroy",
            entry_id = entry.id,
            reason = ?reason,
            "conntrack destroy entry"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::conntrack::proto::udp::UdpProtoState;
    use crate::conntrack::proto::ProtoState;
    use crate::conntrack::tuple::Protocol;

    fn sample_udp_entry(id: u64) -> Arc<ConntrackEntry> {
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

    #[test]
    fn flow_key_stable_for_entry() {
        let e = sample_udp_entry(42);
        let k1 = flow_key_for(&e);
        let k2 = flow_key_for(&e);
        assert_eq!(k1, k2);
    }

    #[test]
    fn flow_key_same_for_original_and_reply_semantics() {
        let e = sample_udp_entry(7);
        let k = flow_key_for(&e);
        assert_eq!(k.entry_id, e.id);
        assert_eq!(k.original, e.original);
    }

    #[test]
    fn distinct_entries_distinct_keys() {
        let a = sample_udp_entry(1);
        let b = sample_udp_entry(2);
        assert_ne!(flow_key_for(&a), flow_key_for(&b));
    }

    #[tokio::test]
    async fn same_entry_reuses_one_handle() {
        let ct = Arc::new(Conntrack::new(Arc::new(crate::conntrack::proto::ProtoRegistry::new()), crate::conntrack::config::ConntrackConfig::default()));
        let sm = SessionManager::new(
            ct,
            TcpL4PipelineFactory::default(),
            UdpL4PipelineFactory::default(),
            IcmpL4PipelineFactory::default(),
        );
        let e = sample_udp_entry(99);
        let h1 = sm.handle_for_entry(&e);
        let h2 = sm.handle_for_entry(&e);
        assert_eq!(sm.active_sessions(), 1);
        let _ = h1;
        let _ = h2;
    }

    #[tokio::test]
    async fn different_entries_different_handles() {
        let ct = Arc::new(Conntrack::new(Arc::new(crate::conntrack::proto::ProtoRegistry::new()), crate::conntrack::config::ConntrackConfig::default()));
        let sm = SessionManager::new(
            ct,
            TcpL4PipelineFactory::default(),
            UdpL4PipelineFactory::default(),
            IcmpL4PipelineFactory::default(),
        );
        let a = sample_udp_entry(10);
        let b = sample_udp_entry(11);
        let _ = sm.handle_for_entry(&a);
        let _ = sm.handle_for_entry(&b);
        assert_eq!(sm.active_sessions(), 2);
    }

    fn minimal_tcp_packet() -> PacketContext {
        use etherparse::PacketBuilder;
        use std::sync::Arc as StdArc;
        let mut raw = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(12345, 80, 1, 65535)
            .write(&mut raw, b"p")
            .unwrap();
        PacketContext::from_raw(raw, StdArc::from("eth0")).unwrap()
    }

    #[tokio::test]
    async fn session_task_ordering_and_lifecycle() {
        let ct = Arc::new(Conntrack::new(Arc::new(crate::conntrack::proto::ProtoRegistry::new()), crate::conntrack::config::ConntrackConfig::default()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let sm = SessionManager::new_with_event_trace(
            ct,
            TcpL4PipelineFactory::default(),
            UdpL4PipelineFactory::default(),
            IcmpL4PipelineFactory::default(),
            log.clone(),
        );

        let entry = sample_udp_entry(500);
        let h = sm.handle_for_entry(&entry);

        let pkt = minimal_tcp_packet();
        h.send(L4Input {
            packet: pkt.clone(),
            dir: Direction::Original,
            entry: entry.clone(),
        })
        .unwrap();
        h.send(L4Input {
            packet: pkt,
            dir: Direction::Reply,
            entry: entry.clone(),
        })
        .unwrap();

        drop(h);
        drop(sm);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let v = log.lock().await;
                if v.len() >= 4 && v[0] == "open" && v[1] == "packet" && v[2] == "packet" && v[3] == "close" {
                    break;
                }
                drop(v);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout waiting for session trace");

        let v = log.lock().await;
        assert_eq!(&v[..], &["open", "packet", "packet", "close"]);
    }
}
