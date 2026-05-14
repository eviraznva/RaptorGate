use std::sync::{Arc, Mutex as StdMutex, Weak};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use etherparse::PacketBuilder;
use tokio::sync::mpsc;

use crate::conntrack::entry::{ConntrackEntry, ConntrackInterfacePath, CtStatus};
use crate::conntrack::observer::{AnomalyKind, CtObserver, DestroyReason};
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

#[derive(Debug)]
pub enum L4Input {
    Bytes { dir: Direction, bytes: Vec<u8> },
    Close { reason: CloseReason },
}

#[derive(Clone)]
pub struct SessionContext {
    flow: FlowKey,
    pub zone: u16,
    pub interfaces: ConntrackInterfacePath,
    manager: Arc<SessionManager>,
}

impl SessionContext {
    pub fn snapshot(entry: &ConntrackEntry, manager: &Arc<SessionManager>) -> Self {
        Self {
            flow: flow_key_for(entry),
            zone: entry.zone,
            interfaces: entry.interface_path(),
            manager: manager.clone(),
        }
    }

    pub fn flow_key(&self) -> FlowKey {
        self.flow
    }

    pub fn invalidate(&self) {
        self.manager.invalidate_session(&self.flow);
    }
}

fn close_reason_from_destroy(r: DestroyReason) -> CloseReason {
    match r {
        DestroyReason::Timeout => CloseReason::Timeout,
        DestroyReason::Manual | DestroyReason::Replaced | DestroyReason::Shutdown => CloseReason::Finished,
        DestroyReason::InvalidatedByStage => CloseReason::Invalidated,
    }
}

fn minimal_stub_packet(iface: Arc<str>) -> PacketContext {
    let mut raw = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(12345, 80, 1, 65535)
        .write(&mut raw, b"")
        .expect("stub packet");
    PacketContext::from_raw(raw, iface).expect("stub packet")
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

    fn on_bytes(&mut self, ctx: &mut (), packet: &mut PacketContext, dir: Direction, payload: &[u8]) -> L4Outcome {
        match self {
            Self::Tcp(p) => p.on_bytes(ctx, packet, dir, payload),
            Self::Udp(p) => p.on_bytes(ctx, packet, dir, payload),
            Self::Icmp(p) => p.on_bytes(ctx, packet, dir, payload),
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

struct SessionManagerObs {
    inner: Weak<SessionManager>,
}

impl CtObserver for SessionManagerObs {
    fn on_new(&self, entry: &ConntrackEntry) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_new(entry);
        }
    }

    fn on_update(&self, entry: &ConntrackEntry, changed: CtStatus) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_update(entry, changed);
        }
    }

    fn on_destroy(&self, entry: &ConntrackEntry, reason: DestroyReason) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_destroy(entry, reason);
        }
    }

    fn on_anomaly(&self, entry: &ConntrackEntry, kind: AnomalyKind) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_anomaly(entry, kind);
        }
    }

    fn on_payload(&self, entry: &ConntrackEntry, dir: Direction, payload: &[u8]) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_payload(entry, dir, payload);
        }
    }
}

pub struct SessionManager {
    self_weak: Weak<SessionManager>,
    ct: Arc<Conntrack>,
    tcp_factory: TcpL4PipelineFactory,
    udp_factory: UdpL4PipelineFactory,
    icmp_factory: IcmpL4PipelineFactory,
    handles: DashMap<FlowKey, mpsc::UnboundedSender<L4Input>>,
    trace: Option<Arc<StdMutex<Vec<String>>>>,
}

impl SessionManager {
    pub fn new(
        ct: Arc<Conntrack>,
        tcp_factory: TcpL4PipelineFactory,
        udp_factory: UdpL4PipelineFactory,
        icmp_factory: IcmpL4PipelineFactory,
    ) -> Arc<Self> {
        let sm = Arc::new_cyclic(|weak| Self {
            self_weak: weak.clone(),
            ct: ct.clone(),
            tcp_factory,
            udp_factory,
            icmp_factory,
            handles: DashMap::new(),
            trace: None,
        });

        sm.ct.register_observer(Arc::new(SessionManagerObs {
            inner: sm.self_weak.clone(),
        }));

        sm
    }

    pub fn new_with_event_trace(
        ct: Arc<Conntrack>,
        tcp_factory: TcpL4PipelineFactory,
        udp_factory: UdpL4PipelineFactory,
        icmp_factory: IcmpL4PipelineFactory,
        trace: Arc<StdMutex<Vec<String>>>,
    ) -> Arc<Self> {
        let sm = Arc::new_cyclic(|weak| Self {
            self_weak: weak.clone(),
            ct: ct.clone(),
            tcp_factory,
            udp_factory,
            icmp_factory,
            handles: DashMap::new(),
            trace: Some(trace),
        });

        sm.ct.register_observer(Arc::new(SessionManagerObs {
            inner: sm.self_weak.clone(),
        }));

        sm
    }

    pub fn conntrack(&self) -> &Arc<Conntrack> {
        &self.ct
    }

    pub fn active_sessions(&self) -> usize {
        self.handles.len()
    }

    pub fn invalidate_session(&self, flow: &FlowKey) {
        let _ = self.ct.destroy_by_id(flow.entry_id, DestroyReason::InvalidatedByStage);
    }

    #[cfg(any(test, feature = "test-capture"))]
    pub fn inject_session_payload(&self, entry: &ConntrackEntry, dir: Direction, payload: &[u8]) {
        self.on_ct_payload(entry, dir, payload);
    }

    fn on_ct_new(&self, entry: &ConntrackEntry) {
        let flow = flow_key_for(entry);

        let (tx, mut rx) = mpsc::unbounded_channel::<L4Input>();

        match self.handles.entry(flow) {
            Entry::Occupied(_) => return,
            Entry::Vacant(v) => {
                v.insert(tx.clone());
            }
        }

        let Some(sm) = self.self_weak.upgrade() else {
            self.handles.remove(&flow);
            return;
        };

        let trace = self.trace.clone();
        let tcp_f = self.tcp_factory;
        let udp_f = self.udp_factory;
        let icmp_f = self.icmp_factory;
        let proto = { entry.proto_state.lock().clone() };
        let session_ctx = SessionContext::snapshot(entry, &sm);
        let iface = session_ctx
            .interfaces
            .original_ingress
            .clone()
            .unwrap_or_else(|| Arc::from("unknown"));

        tokio::spawn(async move {
            let mut pipeline = Phase1NoopPipeline::from_proto(&proto, tcp_f, udp_f, icmp_f);
            let mut l4_ctx = ();

            if let Some(t) = &trace {
                t.lock().expect("trace").push("open".to_string());
            }
            let _ = pipeline.on_session_open(&mut l4_ctx);

            let mut stub = minimal_stub_packet(iface);

            while let Some(msg) = rx.recv().await {
                match msg {
                    L4Input::Bytes { dir, bytes } => {
                        if let Some(t) = &trace {
                            t.lock().expect("trace").push("bytes".to_string());
                        }
                        let _ = pipeline.on_bytes(&mut l4_ctx, &mut stub, dir, &bytes);
                    }
                    L4Input::Close { reason } => {
                        if let Some(t) = &trace {
                            t.lock().expect("trace").push("close".to_string());
                        }
                        let _ = pipeline.on_session_close(&mut l4_ctx, reason);
                        return;
                    }
                }
            }

            if let Some(t) = &trace {
                t.lock().expect("trace").push("close".to_string());
            }
            let _ = pipeline.on_session_close(&mut l4_ctx, CloseReason::Finished);
        });
    }

    fn on_ct_update(&self, _entry: &ConntrackEntry, _changed: CtStatus) {}

    fn on_ct_destroy(&self, entry: &ConntrackEntry, reason: DestroyReason) {
        let flow = flow_key_for(entry);
        let Some((_, tx)) = self.handles.remove(&flow) else {
            return;
        };
        let close = close_reason_from_destroy(reason);
        let _ = tx.send(L4Input::Close { reason: close });
    }

    fn on_ct_anomaly(&self, _entry: &ConntrackEntry, _kind: AnomalyKind) {}

    fn on_ct_payload(&self, entry: &ConntrackEntry, dir: Direction, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }

        let flow = flow_key_for(entry);
        let Some(tx) = self.handles.get(&flow) else {
            return;
        };

        let _ = tx.send(L4Input::Bytes {
            dir,
            bytes: payload.to_vec(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::conntrack::config::ConntrackConfig;
    use crate::conntrack::proto::udp::UdpProtoState;
    use crate::conntrack::proto::ProtoRegistry;

    fn sample_udp_entry(id: u64) -> Arc<ConntrackEntry> {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            2000,
            crate::conntrack::tuple::Protocol::Udp,
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

    #[tokio::test]
    async fn observer_new_payload_destroy_lifecycle() {
        let ct = Arc::new(Conntrack::new(
            Arc::new(ProtoRegistry::new()),
            ConntrackConfig::default(),
        ));
        let log = Arc::new(StdMutex::new(Vec::new()));
        let sm = SessionManager::new_with_event_trace(
            ct.clone(),
            TcpL4PipelineFactory::default(),
            UdpL4PipelineFactory::default(),
            IcmpL4PipelineFactory::default(),
            log.clone(),
        );

        let entry = sample_udp_entry(501);
        assert!(ct.confirm(&entry));
        assert_eq!(sm.active_sessions(), 1);

        sm.inject_session_payload(&entry, Direction::Original, b"a");
        sm.inject_session_payload(&entry, Direction::Reply, b"b");

        ct.destroy(&entry, DestroyReason::Timeout);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let v = log.lock().expect("trace");
                if v.len() >= 4 {
                    break;
                }
                drop(v);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout");

        let v = log.lock().expect("trace");
        assert_eq!(&v[..], &["open", "bytes", "bytes", "close"]);
        assert_eq!(sm.active_sessions(), 0);
    }

    #[tokio::test]
    async fn invalidate_session_closes_and_clears_handle() {
        let ct = Arc::new(Conntrack::new(
            Arc::new(ProtoRegistry::new()),
            ConntrackConfig::default(),
        ));
        let log = Arc::new(StdMutex::new(Vec::new()));
        let sm = SessionManager::new_with_event_trace(
            ct.clone(),
            TcpL4PipelineFactory::default(),
            UdpL4PipelineFactory::default(),
            IcmpL4PipelineFactory::default(),
            log.clone(),
        );

        let entry = sample_udp_entry(502);
        assert!(ct.confirm(&entry));
        let flow = flow_key_for(&entry);

        sm.invalidate_session(&flow);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let v = log.lock().expect("trace");
                if v.len() >= 2 && v[0] == "open" && v[1] == "close" {
                    break;
                }
                drop(v);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout");

        assert_eq!(sm.active_sessions(), 0);
        assert_eq!(ct.entries_count(), 0);
    }
}
