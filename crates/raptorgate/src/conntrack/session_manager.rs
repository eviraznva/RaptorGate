use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::conntrack::entry::CtStatus;
use crate::conntrack::observer::{AnomalyKind, CtObserver, DestroyReason};
use crate::conntrack::proto::ProtoState;
use crate::conntrack::reassembler::DeliveredChunk;
use crate::conntrack::table::Conntrack;
use crate::conntrack::tuple::{Direction, FlowTuple};
use crate::data_plane::packet_context::{PacketContext, PacketId};
use crate::l4::context::SessionContext;
use crate::l4::egress::{policy_release_action, zone_pair_for_session_packet};
use crate::l4::release::{DropReason, ReleaseAction};
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage, TerminateReason};
use crate::l4::{
    IcmpL4PipelineFactory, IcmpNoopPipeline, TcpL4PipelineFactory, TcpNoopPipeline, UdpL4PipelineFactory,
    UdpNoopPipeline,
};
use crate::policy::engine::PolicyEngine;
use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::zones::resolver::ZoneResolver;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub entry_id: u64,
    pub original: FlowTuple,
}

pub fn flow_key_for(entry: &crate::conntrack::entry::ConntrackEntry) -> FlowKey {
    FlowKey {
        entry_id: entry.id,
        original: entry.original,
    }
}

#[derive(Debug)]
pub enum L4Input {
    Bytes {
        dir: Direction,
        bytes: Vec<u8>,
        packet_id: PacketId,
        tcp_payload_start_seq: u32,
    },
    Close {
        reason: CloseReason,
    },
}

struct PendingEntry {
    packet: PacketContext,
    dir: Direction,
}

struct SessionPending {
    map: BTreeMap<PacketId, PendingEntry>,
}

struct SessionManagerObs<ZR, Dns>
where
    ZR: ZoneResolver + Clone + Send + Sync + 'static,
    Dns: DnssecProvider + Send + Sync + 'static,
{
    inner: Weak<SessionManager<ZR, Dns>>,
}

impl<ZR, Dns> CtObserver for SessionManagerObs<ZR, Dns>
where
    ZR: ZoneResolver + Clone + Send + Sync + 'static,
    Dns: DnssecProvider + Send + Sync + 'static,
{
    fn on_new(&self, entry: &crate::conntrack::entry::ConntrackEntry) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_new(entry);
        }
    }

    fn on_update(&self, entry: &crate::conntrack::entry::ConntrackEntry, changed: CtStatus) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_update(entry, changed);
        }
    }

    fn on_destroy(&self, entry: &crate::conntrack::entry::ConntrackEntry, reason: DestroyReason) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_destroy(entry, reason);
        }
    }

    fn on_anomaly(&self, entry: &crate::conntrack::entry::ConntrackEntry, kind: AnomalyKind) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_anomaly(entry, kind);
        }
    }

    fn on_payload(&self, entry: &crate::conntrack::entry::ConntrackEntry, dir: Direction, chunk: &DeliveredChunk) {
        if let Some(s) = self.inner.upgrade() {
            s.on_ct_payload(entry, dir, chunk);
        }
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

    fn protocol(&self) -> crate::dpi::AppProto {
        match self {
            Self::Tcp(p) => p.protocol(),
            Self::Udp(p) => p.protocol(),
            Self::Icmp(p) => p.protocol(),
        }
    }

    fn on_session_open(&mut self, ctx: &mut ()) -> L4Outcome {
        match self {
            Self::Tcp(p) => p.on_session_open(ctx),
            Self::Udp(p) => p.on_session_open(ctx),
            Self::Icmp(p) => p.on_session_open(ctx),
        }
    }

    fn on_bytes(
        &mut self,
        ctx: &mut (),
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        match self {
            Self::Tcp(p) => p.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload),
            Self::Udp(p) => p.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload),
            Self::Icmp(p) => p.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload),
        }
    }

    fn on_session_close(&mut self, ctx: &mut (), reason: CloseReason) {
        match self {
            Self::Tcp(p) => p.on_session_close(ctx, reason),
            Self::Udp(p) => p.on_session_close(ctx, reason),
            Self::Icmp(p) => p.on_session_close(ctx, reason),
        }
    }
}

fn close_reason_from_destroy(r: DestroyReason) -> CloseReason {
    match r {
        DestroyReason::Timeout => CloseReason::Timeout,
        DestroyReason::Manual | DestroyReason::Replaced | DestroyReason::Shutdown => CloseReason::Finished,
        DestroyReason::InvalidatedByStage => CloseReason::Invalidated,
    }
}

fn drop_all_pending(
    pending: &mut SessionPending,
    release_tx: &mpsc::UnboundedSender<ReleaseAction>,
    reason: DropReason,
) {
    while let Some((packet_id, _)) = pending.map.pop_first() {
        let _ = release_tx.send(ReleaseAction::Drop { packet_id, reason });
    }
}

fn handle_outcome<ZR, Dns>(
    outcome: L4Outcome,
    pending: &mut SessionPending,
    release_tx: &mpsc::UnboundedSender<ReleaseAction>,
    policy_engine: &PolicyEngine,
    zone_resolver: &ZR,
    session_ctx: &SessionContext,
    dnssec: Option<&Arc<Dns>>,
) where
    ZR: ZoneResolver,
    Dns: DnssecProvider + Send + Sync + 'static,
{
    match outcome {
        L4Outcome::Continue => {}
        L4Outcome::Forward(ids) => {
            for packet_id in ids {
                let Some(entry) = pending.map.remove(&packet_id) else {
                    continue;
                };
                let zone_pair_id = zone_pair_for_session_packet(session_ctx, entry.dir);
                let action = policy_release_action(
                    policy_engine,
                    zone_resolver,
                    zone_pair_id,
                    entry.packet,
                    session_ctx,
                    dnssec,
                );
                let _ = release_tx.send(action);
            }
        }
        L4Outcome::Terminate { reason: _, reset: _ } => {
            drop_all_pending(pending, release_tx, DropReason::SessionTerminated);
        }
    }
}

pub struct SessionManager<ZR, Dns>
where
    ZR: ZoneResolver,
    Dns: DnssecProvider + Send + Sync + 'static,
{
    self_weak: Weak<SessionManager<ZR, Dns>>,
    ct: Arc<Conntrack>,
    tcp_factory: TcpL4PipelineFactory,
    udp_factory: UdpL4PipelineFactory,
    icmp_factory: IcmpL4PipelineFactory,
    handles: DashMap<FlowKey, mpsc::UnboundedSender<L4Input>>,
    pending_by_flow: DashMap<FlowKey, Arc<StdMutex<SessionPending>>>,
    trace: Option<Arc<StdMutex<Vec<String>>>>,
    observer_events: AtomicUsize,
    release_tx: mpsc::UnboundedSender<ReleaseAction>,
    policy_engine: Arc<PolicyEngine>,
    zone_resolver: ZR,
    dnssec: Option<Arc<Dns>>,
}

pub type SessionManagerDefault = SessionManager<
    crate::zones::resolver::RoutingZoneResolver<crate::interfaces::NetworkInterfaceMonitor>,
    crate::data_plane::dns_inspection::dns_inspection::DnsInspection,
>;

impl<ZR, Dns> SessionManager<ZR, Dns>
where
    ZR: ZoneResolver + Clone + Send + Sync + 'static,
    Dns: DnssecProvider + Send + Sync + 'static,
{
    pub fn new(
        ct: Arc<Conntrack>,
        tcp_factory: TcpL4PipelineFactory,
        udp_factory: UdpL4PipelineFactory,
        icmp_factory: IcmpL4PipelineFactory,
        policy_engine: Arc<PolicyEngine>,
        zone_resolver: ZR,
        dnssec: Option<Arc<Dns>>,
        release_tx: mpsc::UnboundedSender<ReleaseAction>,
    ) -> Arc<Self> {
        let sm = Arc::new_cyclic(|weak| Self {
            self_weak: weak.clone(),
            ct: ct.clone(),
            tcp_factory,
            udp_factory,
            icmp_factory,
            handles: DashMap::new(),
            pending_by_flow: DashMap::new(),
            trace: None,
            observer_events: AtomicUsize::new(0),
            release_tx,
            policy_engine,
            zone_resolver,
            dnssec,
        });

        sm.ct.register_observer(Arc::new(SessionManagerObs::<ZR, Dns> {
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
        policy_engine: Arc<PolicyEngine>,
        zone_resolver: ZR,
        dnssec: Option<Arc<Dns>>,
        release_tx: mpsc::UnboundedSender<ReleaseAction>,
    ) -> Arc<Self> {
        let sm = Arc::new_cyclic(|weak| Self {
            self_weak: weak.clone(),
            ct: ct.clone(),
            tcp_factory,
            udp_factory,
            icmp_factory,
            handles: DashMap::new(),
            pending_by_flow: DashMap::new(),
            trace: Some(trace),
            observer_events: AtomicUsize::new(0),
            release_tx,
            policy_engine,
            zone_resolver,
            dnssec,
        });

        sm.ct.register_observer(Arc::new(SessionManagerObs::<ZR, Dns> {
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

    pub fn observer_event_count(&self) -> usize {
        self.observer_events.load(Ordering::Relaxed)
    }

    pub fn has_session_handle(&self, entry: &crate::conntrack::entry::ConntrackEntry) -> bool {
        self.handles.contains_key(&flow_key_for(entry))
    }

    pub fn admit_packet(
        &self,
        entry: &crate::conntrack::entry::ConntrackEntry,
        packet: PacketContext,
        dir: Direction,
    ) {
        let flow = flow_key_for(entry);
        let Some(pending_arc) = self.pending_by_flow.get(&flow) else {
            return;
        };
        let mut pending = pending_arc.lock().expect("session pending");
        pending.map.insert(packet.packet_id(), PendingEntry { packet, dir });
    }

    pub fn invalidate_session(&self, flow: &FlowKey) {
        let _ = self.ct.destroy_by_id(flow.entry_id, DestroyReason::InvalidatedByStage);
    }

    #[cfg(any(test, feature = "test-capture"))]
    pub fn inject_session_payload(
        &self,
        entry: &crate::conntrack::entry::ConntrackEntry,
        dir: Direction,
        payload: &[u8],
        packet_id: PacketId,
    ) {
        let chunk = DeliveredChunk {
            packet_id,
            payload: payload.to_vec(),
            tcp_payload_start_seq: 0,
        };
        self.on_ct_payload(entry, dir, &chunk);
    }

    fn on_ct_new(&self, entry: &crate::conntrack::entry::ConntrackEntry) {
        self.observer_events.fetch_add(1, Ordering::Relaxed);
        let flow = flow_key_for(entry);

        let (tx, mut rx) = mpsc::unbounded_channel::<L4Input>();

        match self.handles.entry(flow) {
            Entry::Occupied(_) => return,
            Entry::Vacant(v) => {
                v.insert(tx.clone());
            }
        }

        let pending_arc = Arc::new(StdMutex::new(SessionPending {
            map: BTreeMap::new(),
        }));
        self.pending_by_flow.insert(flow, Arc::clone(&pending_arc));

        let Some(sm) = self.self_weak.upgrade() else {
            self.handles.remove(&flow);
            self.pending_by_flow.remove(&flow);
            return;
        };

        let trace = self.trace.clone();
        let tcp_f = self.tcp_factory;
        let udp_f = self.udp_factory;
        let icmp_f = self.icmp_factory;
        let proto = { entry.proto_state.lock().clone() };
        let entry_arc = self
            .ct
            .find_by_id(entry.id)
            .unwrap_or_else(|| panic!("on_new for missing entry {}", entry.id));
        let mut session_ctx = SessionContext::open(entry_arc, &self.zone_resolver);
        let mut l4_ctx = ();
        let policy_engine = Arc::clone(&self.policy_engine);
        let zone_resolver = self.zone_resolver.clone();
        let dnssec = self.dnssec.clone();
        let release_tx = self.release_tx.clone();
        let ct = Arc::clone(&self.ct);
        let flow_key = flow;

        tokio::spawn(async move {
            let mut pipeline = Phase1NoopPipeline::from_proto(&proto, tcp_f, udp_f, icmp_f);

            if let Some(t) = &trace {
                t.lock().expect("trace").push("open".to_string());
            }
            let _ = pipeline.on_session_open(&mut l4_ctx);

            while let Some(msg) = rx.recv().await {
                let mut pending = pending_arc.lock().expect("session pending");
                match msg {
                    L4Input::Bytes {
                        dir,
                        bytes,
                        packet_id,
                        tcp_payload_start_seq,
                    } => {
                        if let Some(t) = &trace {
                            t.lock().expect("trace").push("bytes".to_string());
                        }
                        let outcome = pipeline.on_bytes(
                            &mut l4_ctx,
                            packet_id,
                            dir,
                            tcp_payload_start_seq,
                            &bytes,
                        );
                        handle_outcome(
                            outcome,
                            &mut pending,
                            &release_tx,
                            &policy_engine,
                            &zone_resolver,
                            &session_ctx,
                            dnssec.as_ref(),
                        );
                    }
                    L4Input::Close { reason } => {
                        if let Some(t) = &trace {
                            t.lock().expect("trace").push("close".to_string());
                        }
                        pipeline.on_session_close(&mut l4_ctx, reason);
                        drop_all_pending(&mut pending, &release_tx, DropReason::SessionClosed);
                        sm.pending_by_flow.remove(&flow_key);
                        sm.handles.remove(&flow_key);
                        return;
                    }
                }
            }

            if let Some(t) = &trace {
                t.lock().expect("trace").push("close".to_string());
            }
            let mut pending = pending_arc.lock().expect("session pending");
            pipeline.on_session_close(&mut l4_ctx, CloseReason::Finished);
            drop_all_pending(&mut pending, &release_tx, DropReason::SessionClosed);
            sm.pending_by_flow.remove(&flow_key);
            sm.handles.remove(&flow_key);
        });
    }

    fn on_ct_update(&self, _entry: &crate::conntrack::entry::ConntrackEntry, _changed: CtStatus) {}

    fn on_ct_destroy(&self, entry: &crate::conntrack::entry::ConntrackEntry, reason: DestroyReason) {
        self.observer_events.fetch_add(1, Ordering::Relaxed);
        let flow = flow_key_for(entry);
        let Some((_, tx)) = self.handles.remove(&flow) else {
            return;
        };
        let close = close_reason_from_destroy(reason);
        let _ = tx.send(L4Input::Close { reason: close });
        self.pending_by_flow.remove(&flow);
    }

    fn on_ct_anomaly(&self, _entry: &crate::conntrack::entry::ConntrackEntry, _kind: AnomalyKind) {}

    fn on_ct_payload(
        &self,
        entry: &crate::conntrack::entry::ConntrackEntry,
        dir: Direction,
        chunk: &DeliveredChunk,
    ) {
        self.observer_events.fetch_add(1, Ordering::Relaxed);
        if chunk.payload.is_empty() {
            return;
        }

        let flow = flow_key_for(entry);
        let Some(tx) = self.handles.get(&flow) else {
            return;
        };

        let _ = tx.send(L4Input::Bytes {
            dir,
            bytes: chunk.payload.clone(),
            packet_id: chunk.packet_id,
            tcp_payload_start_seq: chunk.tcp_payload_start_seq,
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
    use crate::policy::engine::PolicyEngine;
    use crate::zones::resolver::ZoneResolver;
    use crate::zones::{ResolvedZonePair, ZonePairId};

    #[derive(Clone)]
    struct StubZoneResolver;

    impl ZoneResolver for StubZoneResolver {
        fn resolve(&self, _src_interface_name: &str, _dst_ip: IpAddr) -> Option<ResolvedZonePair> {
            Some(ResolvedZonePair {
                id: ZonePairId::from(uuid::Uuid::nil()),
                default_policy: crate::zones::DefaultPolicy::Allow,
            })
        }

        fn resolve_bidirectional(&self, _src_ip: IpAddr, _dst_ip: IpAddr) -> crate::zones::DirectionalZonePairs {
            let pair = ResolvedZonePair {
                id: ZonePairId::from(uuid::Uuid::nil()),
                default_policy: crate::zones::DefaultPolicy::Allow,
            };
            crate::zones::DirectionalZonePairs {
                forward: Some(pair.clone()),
                reverse: Some(pair),
            }
        }
    }

    struct NoDnssec;

    impl DnssecProvider for NoDnssec {
        fn check_domain(&self, _domain: &str, _qtype: Option<crate::dpi::parsers::dns::DnsRecordType>) -> crate::data_plane::dns_inspection::dnssec::DnssecResult {
            crate::data_plane::dns_inspection::dnssec::DnssecResult::not_checked()
        }
    }

    fn sample_udp_entry(id: u64) -> Arc<crate::conntrack::entry::ConntrackEntry> {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            2000,
            crate::conntrack::tuple::Protocol::Udp,
        );

        Arc::new(crate::conntrack::entry::ConntrackEntry::new(
            id,
            tuple,
            ProtoState::Udp(UdpProtoState::default()),
            Duration::from_secs(60),
            0,
        ))
    }

    fn test_session_manager(trace: Option<Arc<StdMutex<Vec<String>>>>) -> (Arc<SessionManager<StubZoneResolver, NoDnssec>>, mpsc::UnboundedReceiver<ReleaseAction>) {
        let ct = Arc::new(Conntrack::new(
            Arc::new(ProtoRegistry::new()),
            ConntrackConfig::default(),
        ));
        let (release_tx, release_rx) = mpsc::unbounded_channel();
        let policies = std::collections::HashMap::new();
        let zone_pairs = std::collections::HashMap::new();
        let policy_engine = Arc::new(PolicyEngine::from_policies(&policies, &zone_pairs).expect("policy engine"));

        let sm = if let Some(log) = trace {
            SessionManager::new_with_event_trace(
                ct,
                TcpL4PipelineFactory::default(),
                UdpL4PipelineFactory::default(),
                IcmpL4PipelineFactory::default(),
                log,
                policy_engine,
                StubZoneResolver,
                None,
                release_tx,
            )
        } else {
            SessionManager::new(
                ct,
                TcpL4PipelineFactory::default(),
                UdpL4PipelineFactory::default(),
                IcmpL4PipelineFactory::default(),
                policy_engine,
                StubZoneResolver,
                None,
                release_tx,
            )
        };
        (sm, release_rx)
    }

    #[tokio::test]
    async fn observer_new_payload_destroy_lifecycle() {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let (sm, _rx) = test_session_manager(Some(log.clone()));
        let ct = sm.conntrack().clone();

        let entry = sample_udp_entry(501);
        assert!(ct.confirm(&entry));
        assert_eq!(sm.active_sessions(), 1);

        let pid = PacketId::next();
        sm.inject_session_payload(&entry, Direction::Original, b"a", pid);

        ct.destroy(&entry, DestroyReason::Timeout);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let v = log.lock().expect("trace");
                if v.len() >= 3 {
                    break;
                }
                drop(v);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timeout");

        let v = log.lock().expect("trace");
        assert_eq!(&v[..], &["open", "bytes", "close"]);
        assert_eq!(sm.active_sessions(), 0);
    }

    #[tokio::test]
    async fn admit_bytes_forward_releases_packet() {
        let (sm, mut release_rx) = test_session_manager(None);
        let ct = sm.conntrack().clone();
        let entry = sample_udp_entry(601);
        assert!(ct.confirm(&entry));

        let mut raw = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(1000, 2000)
            .write(&mut raw, b"payload")
            .expect("packet");
        let packet = PacketContext::from_raw(raw, Arc::from("eth0")).expect("packet");
        let packet_id = packet.packet_id();

        sm.admit_packet(&entry, packet, Direction::Original);
        sm.inject_session_payload(&entry, Direction::Original, b"payload", packet_id);

        let action = tokio::time::timeout(Duration::from_secs(2), release_rx.recv())
            .await
            .expect("timeout")
            .expect("release");

        match action {
            ReleaseAction::Forward { packet } => assert_eq!(packet.packet_id(), packet_id),
            ReleaseAction::Drop { .. } => panic!("expected forward"),
        }
    }
}
