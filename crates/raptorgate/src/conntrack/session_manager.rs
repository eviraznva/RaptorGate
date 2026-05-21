use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use etherparse::TransportSlice;
use tokio::sync::mpsc;

use crate::conntrack::entry::CtStatus;
use crate::conntrack::observer::{AnomalyKind, CtObserver, DestroyReason};
use crate::conntrack::proto::ProtoState;
use crate::conntrack::reassembler::DeliveredChunk;
use crate::conntrack::table::Conntrack;
use crate::conntrack::tuple::{Direction, FlowTuple};
use crate::data_plane::dns_inspection::dns_inspection::{BlocklistVerdict, DnsInspection, EchMitigationVerdict};
use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::data_plane::dns_inspection::tunneling_detector::DnsInspectionVerdict;
use crate::data_plane::packet_context::{PacketContext, PacketId};
use crate::dpi::{AppProto, DpiClassifier, InspectResult};
use crate::l4::context::SessionContext;
use crate::l4::egress::{policy_release_action, zone_pair_for_session_packet};
use crate::l4::release::{DropReason, ReleaseAction};
use crate::l4::reset::{tcp_reset_segment_to_raw, TcpResetAction};
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage};
use crate::l4::{
    IcmpL4PipelineFactory, IcmpNoopPipeline, TcpL4PipelineFactory, TcpSessionPipeline, UdpL4PipelineFactory,
    UdpNoopPipeline,
};
use crate::policy::engine::PolicyEngine;
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

struct PendingPayload {
    dir: Direction,
    bytes: Vec<u8>,
    tcp_payload_start_seq: u32,
}

struct SessionPending {
    map: BTreeMap<PacketId, PendingEntry>,
    payloads: BTreeMap<PacketId, Vec<PendingPayload>>,
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

enum Phase1L4Pipeline<ZR: ZoneResolver + Send + Sync + 'static> {
    Tcp(TcpSessionPipeline<ZR>),
    Udp(UdpNoopPipeline),
    Icmp(IcmpNoopPipeline),
}

impl<ZR: ZoneResolver + Send + Sync + 'static> Phase1L4Pipeline<ZR> {
    fn from_proto(
        proto: &ProtoState,
        tcp_f: TcpL4PipelineFactory<ZR>,
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

    fn on_session_open(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        match self {
            Self::Tcp(p) => p.on_session_open(ctx),
            Self::Udp(p) => p.on_session_open(ctx),
            Self::Icmp(p) => p.on_session_open(ctx),
        }
    }

    fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
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

    fn on_session_close(&mut self, ctx: &mut SessionContext, reason: CloseReason) {
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
        let _ = release_tx.send(ReleaseAction::Drop { packet_id, reason, temp_dst_port: None });
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
    ct: &Arc<Conntrack>,
    entry_id: u64,
) -> bool
where
    ZR: ZoneResolver,
    Dns: DnssecProvider + Send + Sync + 'static,
{
    match outcome {
        L4Outcome::Continue => false,
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
            false
        }
        L4Outcome::Terminate { reason: _, reset } => {
            drop_all_pending(pending, release_tx, DropReason::SessionTerminated);
            if reset {
                match session_ctx.build_tcp_reset() {
                    TcpResetAction::EmitRstPair { original, reply } => {
                        for seg in [&original, &reply] {
                            let Some(raw) = tcp_reset_segment_to_raw(seg) else {
                                continue;
                            };
                            let iface = seg
                                .ingress_iface
                                .clone()
                                .unwrap_or_else(|| std::sync::Arc::from("eth0"));
                            if let Ok(pkt) = PacketContext::from_raw(raw, iface) {
                                let _ = release_tx.send(ReleaseAction::Forward { packet: pkt });
                            }
                        }
                    }
                    TcpResetAction::Unavailable { .. } => {}
                }
            }
            let _ = ct.destroy_by_id(entry_id, DestroyReason::InvalidatedByStage);
            true
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
    tcp_factory: TcpL4PipelineFactory<ZR>,
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
    dpi_classifier: Option<Arc<DpiClassifier>>,
    dns_inspection: Option<Arc<DnsInspection>>,
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
        tcp_factory: TcpL4PipelineFactory<ZR>,
        udp_factory: UdpL4PipelineFactory,
        icmp_factory: IcmpL4PipelineFactory,
        policy_engine: Arc<PolicyEngine>,
        zone_resolver: ZR,
        dnssec: Option<Arc<Dns>>,
        dpi_classifier: Option<Arc<DpiClassifier>>,
        dns_inspection: Option<Arc<DnsInspection>>,
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
            dpi_classifier,
            dns_inspection,
        });

        sm.ct.register_observer(Arc::new(SessionManagerObs::<ZR, Dns> {
            inner: sm.self_weak.clone(),
        }));

        sm
    }

    pub fn new_with_event_trace(
        ct: Arc<Conntrack>,
        tcp_factory: TcpL4PipelineFactory<ZR>,
        udp_factory: UdpL4PipelineFactory,
        icmp_factory: IcmpL4PipelineFactory,
        trace: Arc<StdMutex<Vec<String>>>,
        policy_engine: Arc<PolicyEngine>,
        zone_resolver: ZR,
        dnssec: Option<Arc<Dns>>,
        dpi_classifier: Option<Arc<DpiClassifier>>,
        dns_inspection: Option<Arc<DnsInspection>>,
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
            dpi_classifier,
            dns_inspection,
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

    pub fn inspect_dns_or_drop(
        &self,
        entry: &crate::conntrack::entry::ConntrackEntry,
        packet: &mut PacketContext,
        dir: Direction,
    ) -> bool {
        tracing::debug!(
            event = "session.inspect_dns.called",
            flow_id = entry.id,
            has_classifier = self.dpi_classifier.is_some(),
            has_inspection = self.dns_inspection.is_some(),
            "inspect_dns_or_drop called"
        );
        let Some(reason) = self.inspect_before_admit(packet) else {
            return false;
        };
        let packet_id = packet.packet_id();
        let temp_dst_port = Some(match dir {
            Direction::Original => entry.original.dst_port,
            Direction::Reply => entry.reply().dst_port,
        });
        packet.with_warnings_mut(|w| w.push(reason.clone()));
        tracing::warn!(
            event = "session.dns_inspection.blocked",
            flow_id = entry.id,
            packet_id = packet_id.0,
            reason = %reason,
            "session DNS inspection blocked packet"
        );
        let _ = self.release_tx.send(ReleaseAction::Drop {
            packet_id,
            reason: DropReason::StageDropped,
            temp_dst_port,
        });
        let _ = self.ct.destroy_by_id(entry.id, DestroyReason::InvalidatedByStage);
        true
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
        let Some(tx) = self.handles.get(&flow).map(|tx| tx.clone()) else {
            return;
        };
        let packet_id = packet.packet_id();
        let empty_payload_start_seq = match packet.borrow_sliced_packet().transport.as_ref() {
            Some(TransportSlice::Tcp(tcp)) if tcp.payload().is_empty() => Some(tcp.sequence_number()),
            Some(TransportSlice::Udp(udp)) if udp.payload().is_empty() => {
                Some(0)
            }
            Some(TransportSlice::Icmpv4(icmp)) if icmp.payload().is_empty() => {
                Some(0)
            }
            Some(TransportSlice::Icmpv6(icmp)) if icmp.payload().is_empty() => {
                Some(0)
            }
            _ => None,
        };
        let queued_payloads = {
            let mut pending = pending_arc.lock().expect("session pending");
            pending.map.insert(packet_id, PendingEntry { packet, dir });
            pending.payloads.remove(&packet_id).unwrap_or_default()
        };

        for payload in queued_payloads {
            let _ = tx.send(L4Input::Bytes {
                dir: payload.dir,
                bytes: payload.bytes,
                packet_id,
                tcp_payload_start_seq: payload.tcp_payload_start_seq,
            });
        }

        if let Some(tcp_payload_start_seq) = empty_payload_start_seq {
            let _ = tx.send(L4Input::Bytes {
                dir,
                bytes: Vec::new(),
                packet_id,
                tcp_payload_start_seq,
            });
        }
    }

    fn inspect_before_admit(&self, packet: &mut PacketContext) -> Option<String> {
        let Some(classifier) = &self.dpi_classifier else {
            tracing::debug!(event = "session.inspect_dns.no_classifier", "no classifier");
            return None;
        };

        let classify_result = classifier.inspect_packet(packet.borrow_sliced_packet());
        let classify_kind = match &classify_result {
            InspectResult::Done(_) => "done",
            InspectResult::NeedMore => "need_more",
            InspectResult::Skipped => "skipped",
        };
        if let InspectResult::Done(mut dpi_ctx) = classify_result {
            if let Some(existing) = packet.borrow_dpi_ctx().as_ref() {
                dpi_ctx.decrypted |= existing.decrypted;
                dpi_ctx.src_port = dpi_ctx.src_port.or(existing.src_port);
                dpi_ctx.dst_port = dpi_ctx.dst_port.or(existing.dst_port);
            }
            packet.with_dpi_ctx_mut(|c| *c = Some(dpi_ctx));
        }

        let Some(inspection) = &self.dns_inspection else {
            tracing::debug!(event = "session.inspect_dns.no_inspection", classify = classify_kind, "no inspection module");
            return None;
        };

        let Some(dpi_ctx) = packet.borrow_dpi_ctx().clone() else {
            tracing::debug!(event = "session.inspect_dns.no_dpi_ctx", classify = classify_kind, "no dpi ctx");
            return None;
        };
        tracing::debug!(
            event = "session.inspect_dns.classified",
            classify = classify_kind,
            app_proto = ?dpi_ctx.app_proto,
            dns_query = ?dpi_ctx.dns_query_name,
            "classified packet"
        );
        if dpi_ctx.app_proto != Some(AppProto::Dns) {
            return None;
        }

        if let Some(domain) = dpi_ctx.dns_query_name.as_deref() {
            if let BlocklistVerdict::Block(msg) = inspection.check_blocklist(domain) {
                return Some(msg);
            }
        }

        if let (Some(domain), Some(qtype)) = (dpi_ctx.dns_query_name.as_deref(), dpi_ctx.dns_query_type) {
            if let DnsInspectionVerdict::Block(msg) = inspection.inspect_tunneling(domain, &qtype) {
                return Some(msg);
            }
        }

        if dpi_ctx.dns_is_response == Some(true) && dpi_ctx.dns_has_ech_hints {
            if let Some(domain) = dpi_ctx.dns_query_name.as_deref() {
                if let EchMitigationVerdict::Block(msg) = inspection.inspect_ech(domain, true) {
                    return Some(msg);
                }
            }
        }

        None
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
            payloads: BTreeMap::new(),
        }));
        self.pending_by_flow.insert(flow, Arc::clone(&pending_arc));

        let Some(sm) = self.self_weak.upgrade() else {
            self.handles.remove(&flow);
            self.pending_by_flow.remove(&flow);
            return;
        };

        let trace = self.trace.clone();
        let tcp_f = self.tcp_factory.clone();
        let udp_f = self.udp_factory;
        let icmp_f = self.icmp_factory;
        let proto = { entry.proto_state.lock().clone() };
        let entry_arc = self
            .ct
            .find_by_id(entry.id)
            .unwrap_or_else(|| panic!("on_new for missing entry {}", entry.id));
        let mut session_ctx = SessionContext::open(entry_arc, &self.zone_resolver);
        let entry_id = session_ctx.entry().id;
        let policy_engine = Arc::clone(&self.policy_engine);
        let zone_resolver = self.zone_resolver.clone();
        let dnssec = self.dnssec.clone();
        let release_tx = self.release_tx.clone();
        let ct = Arc::clone(&self.ct);
        let flow_key = flow;

        tokio::spawn(async move {
            let mut pipeline = Phase1L4Pipeline::from_proto(&proto, tcp_f, udp_f, icmp_f);

            if let Some(t) = &trace {
                t.lock().expect("trace").push("open".to_string());
            }
            let _ = pipeline.on_session_open(&mut session_ctx);

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
                            &mut session_ctx,
                            packet_id,
                            dir,
                            tcp_payload_start_seq,
                            &bytes,
                        );
                        let terminate = handle_outcome(
                            outcome,
                            &mut pending,
                            &release_tx,
                            &policy_engine,
                            &zone_resolver,
                            &session_ctx,
                            dnssec.as_ref(),
                            &ct,
                            entry_id,
                        );
                        if terminate {
                            return;
                        }
                    }
                    L4Input::Close { reason } => {
                        if let Some(t) = &trace {
                            t.lock().expect("trace").push("close".to_string());
                        }
                        pipeline.on_session_close(&mut session_ctx, reason);
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
            pipeline.on_session_close(&mut session_ctx, CloseReason::Finished);
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

        if let Some(pending_arc) = self.pending_by_flow.get(&flow) {
            let mut pending = pending_arc.lock().expect("session pending");
            if !pending.map.contains_key(&chunk.packet_id) {
                pending.payloads.entry(chunk.packet_id).or_default().push(PendingPayload {
                    dir,
                    bytes: chunk.payload.clone(),
                    tcp_payload_start_seq: chunk.tcp_payload_start_seq,
                });
                return;
            }
        }

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
    use crate::data_plane::dns_inspection::config::DnsInspectionConfig;
    use crate::data_plane::dns_inspection::dns_inspection::DnsInspection;
    use crate::dpi::DpiClassifier;
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

    fn sample_dns_entry(id: u64) -> Arc<crate::conntrack::entry::ConntrackEntry> {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            53,
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

    fn dns_query(name: &str) -> Vec<u8> {
        let mut payload = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in name.split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        payload
    }

    fn sample_tcp_entry_established(id: u64) -> Arc<crate::conntrack::entry::ConntrackEntry> {
        use crate::conntrack::proto::tcp::{TcpConntrack, TcpProtoState};

        let mut tcp = TcpProtoState::default();
        tcp.state = TcpConntrack::Established;
        tcp.seen[0].last_seq = 500;
        tcp.seen[0].last_ack = 600;
        tcp.seen[1].last_seq = 700;
        tcp.seen[1].last_ack = 800;

        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            crate::conntrack::tuple::Protocol::Tcp,
        );

        Arc::new(crate::conntrack::entry::ConntrackEntry::new(
            id,
            tuple,
            ProtoState::Tcp(tcp),
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
                TcpL4PipelineFactory::<StubZoneResolver>::new_force_terminate(),
                UdpL4PipelineFactory::default(),
                IcmpL4PipelineFactory::default(),
                log,
                policy_engine,
                StubZoneResolver,
                None,
                None,
                None,
                release_tx,
            )
        } else {
            SessionManager::new(
                ct,
                TcpL4PipelineFactory::<StubZoneResolver>::new_force_terminate(),
                UdpL4PipelineFactory::default(),
                IcmpL4PipelineFactory::default(),
                policy_engine,
                StubZoneResolver,
                None,
                None,
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

        let mut raw = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(1000, 2000)
            .write(&mut raw, b"a")
            .expect("packet");
        let packet = PacketContext::from_raw(raw, Arc::from("eth0")).expect("packet");
        let pid = packet.packet_id();
        sm.admit_packet(&entry, packet, Direction::Original);
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

    #[tokio::test]
    async fn dns_blocklist_drops_before_session_release() {
        let ct = Arc::new(Conntrack::new(
            Arc::new(ProtoRegistry::new()),
            ConntrackConfig::default(),
        ));
        let (release_tx, mut release_rx) = mpsc::unbounded_channel();
        let policies = std::collections::HashMap::new();
        let zone_pairs = std::collections::HashMap::new();
        let policy_engine = Arc::new(PolicyEngine::from_policies(&policies, &zone_pairs).expect("policy engine"));
        let mut dns_config = DnsInspectionConfig::default();
        dns_config.general.enabled = true;
        dns_config.blocklist.enabled = true;
        dns_config.blocklist.domains = vec!["blocked.test".to_string()];
        let dns_inspection = DnsInspection::new(dns_config).expect("dns inspection");
        let sm = SessionManager::<StubZoneResolver, NoDnssec>::new(
            Arc::clone(&ct),
            TcpL4PipelineFactory::<StubZoneResolver>::new_force_terminate(),
            UdpL4PipelineFactory::default(),
            IcmpL4PipelineFactory::default(),
            policy_engine,
            StubZoneResolver,
            None,
            Some(Arc::new(DpiClassifier::new())),
            Some(dns_inspection),
            release_tx,
        );

        let entry = sample_dns_entry(701);
        assert!(ct.confirm(&entry));

        let mut raw = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(12345, 53)
            .write(&mut raw, &dns_query("blocked.test"))
            .expect("packet");
        let mut packet = PacketContext::from_raw(raw, Arc::from("eth0")).expect("packet");
        let packet_id = packet.packet_id();

        let dropped = sm.inspect_dns_or_drop(&entry, &mut packet, Direction::Original);
        assert!(dropped, "inspect_dns_or_drop should signal drop");

        let action = tokio::time::timeout(Duration::from_secs(2), release_rx.recv())
            .await
            .expect("timeout")
            .expect("release");

        match action {
            ReleaseAction::Drop { packet_id: dropped, reason, temp_dst_port } => {
                assert_eq!(dropped, packet_id);
                assert_eq!(reason, DropReason::StageDropped);
                assert_eq!(temp_dst_port, Some(53));
            }
            ReleaseAction::Forward { .. } => panic!("expected drop"),
        }
        assert!(ct.find_by_id(entry.id).is_none(), "blocked DNS flow should be destroyed");
    }

    #[tokio::test]
    async fn payload_before_admit_is_replayed_when_packet_is_admitted() {
        let (sm, mut release_rx) = test_session_manager(None);
        let ct = sm.conntrack().clone();
        let entry = sample_udp_entry(602);
        assert!(ct.confirm(&entry));

        let mut raw = Vec::new();
        etherparse::PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(1000, 2000)
            .write(&mut raw, b"payload")
            .expect("packet");
        let packet = PacketContext::from_raw(raw, Arc::from("eth0")).expect("packet");
        let packet_id = packet.packet_id();

        sm.inject_session_payload(&entry, Direction::Original, b"payload", packet_id);
        sm.admit_packet(&entry, packet, Direction::Original);

        let action = tokio::time::timeout(Duration::from_secs(2), release_rx.recv())
            .await
            .expect("timeout")
            .expect("release");

        match action {
            ReleaseAction::Forward { packet } => assert_eq!(packet.packet_id(), packet_id),
            ReleaseAction::Drop { .. } => panic!("expected forward"),
        }
    }

    #[tokio::test]
    async fn l4_terminate_reset_emits_rst_and_destroy() {
        let (sm, mut release_rx) = test_session_manager(None);
        let ct = sm.conntrack().clone();
        let entry = sample_tcp_entry_established(901);
        assert!(ct.confirm(&entry));

        let mut raw = Vec::new();
        etherparse::PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(12345, 80, 1000, 2000)
            .write(&mut raw, b"x")
            .expect("packet");
        let packet = PacketContext::from_raw(raw, Arc::from("eth0")).expect("packet");
        let pid = packet.packet_id();
        sm.admit_packet(entry.as_ref(), packet, Direction::Original);
        sm.inject_session_payload(entry.as_ref(), Direction::Original, b"x", pid);

        let mut forwards = 0;
        let mut drops = 0;
        for _ in 0..8 {
            let action = tokio::time::timeout(Duration::from_secs(2), release_rx.recv())
                .await
                .expect("timeout")
                .expect("closed");
            match action {
                ReleaseAction::Forward { .. } => forwards += 1,
                ReleaseAction::Drop { .. } => drops += 1,
            }
            if forwards >= 2 {
                break;
            }
        }

        assert_eq!(drops, 1, "pending should drop as SessionTerminated");
        assert!(forwards >= 2, "expected two RST forwards, got {forwards}");
        assert!(ct.find_by_id(entry.id).is_none(), "flow should be destroyed");
    }
}
