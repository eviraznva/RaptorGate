use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use etherparse::{NetSlice, TransportSlice};
use tokio::sync::Mutex;

use crate::{
    config::{provider::AppConfigProvider, AppConfig},
    data_plane::{
        dns_inspection::dns_inspection::{BlocklistVerdict, DnsInspection, EchMitigationVerdict},
        ips::ips::{Ips, IpsSignatureMatch, IpsVerdict},
        nat::NatEngine,
        packet_context::PacketContext,
        tcp_session_tracker::TcpSessionTracker,
    },
    dpi::{DpiClassifier, FlowKey, InspectResult},
    events::{self, Event, EventKind},
    ml::{MlPacketInspector, MlPrediction},
    packet_validator::validate,
    pipeline::{Stage, StageOutcome},
    policy::provider::DiskPolicyProvider,
    rule_tree::{ArrivalInfo, Verdict},
};

use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::data_plane::dns_inspection::tunneling_detector::DnsInspectionVerdict;
use crate::dpi::AppProto;
use crate::interfaces::InterfaceMonitor;
use crate::policy::policy_evaluator::{DnsEvalContext, PolicyEvalContext};

#[derive(Clone)]
pub struct ValidationStage;

impl Stage for ValidationStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        matches!(
            &ctx.borrow_sliced_packet().net,
            Some(NetSlice::Ipv4(_) | NetSlice::Ipv6(_))
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        match validate(ctx.borrow_sliced_packet()) {
            Ok(()) => StageOutcome::Continue,
            Err(e) => {
                log_packet_decision(
                    ctx,
                    "packet.validation.failed",
                    "validation",
                    "drop",
                    &e.to_string(),
                );
                StageOutcome::Halt
            }
        }
    }
}

#[derive(Clone)]
pub struct LocalOwnershipStage {
    pub config_provider: Arc<AppConfigProvider>,
    pub local_ips: Arc<HashSet<IpAddr>>,
}

impl Stage for LocalOwnershipStage {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        if packet_is_decrypted(ctx) {
            return StageOutcome::Continue;
        }

        let Some(dst_ip) = packet_destination_ip(ctx) else {
            return StageOutcome::Continue;
        };

        if self.local_ips.contains(&dst_ip) {
            tracing::trace!(dst_ip = %dst_ip, iface = %ctx.borrow_src_interface(), "packet owned by local stack");
            return StageOutcome::Halt;
        }

        let config = self.config_provider.get_config();
        if should_halt_for_tls_redirect(ctx, &config) {
            tracing::trace!(
                dst_ip = %dst_ip,
                iface = %ctx.borrow_src_interface(),
                "packet owned by tls redirect"
            );
            return StageOutcome::Halt;
        }

        StageOutcome::Continue
    }
}

fn packet_destination_ip(ctx: &PacketContext) -> Option<IpAddr> {
    match &ctx.borrow_sliced_packet().net {
        Some(NetSlice::Ipv4(ipv4)) => Some(IpAddr::V4(ipv4.header().destination_addr())),
        Some(NetSlice::Ipv6(ipv6)) => Some(IpAddr::V6(ipv6.header().destination_addr())),
        _ => None,
    }
}

fn should_halt_for_tls_redirect(ctx: &PacketContext, config: &AppConfig) -> bool {
    if !config.ssl_inspection_enabled {
        return false;
    }

    if !config
        .capture_interfaces
        .iter()
        .any(|iface| iface.as_str() == ctx.borrow_src_interface().as_ref())
    {
        return false;
    }

    matches!(
        &ctx.borrow_sliced_packet().transport,
        Some(TransportSlice::Tcp(tcp))
            if config.tls_inspection_ports.contains(&tcp.destination_port())
    )
}

fn packet_is_decrypted(ctx: &PacketContext) -> bool {
    ctx.borrow_dpi_ctx()
        .as_ref()
        .is_some_and(|dpi_ctx| dpi_ctx.decrypted)
}

#[derive(Clone)]
pub struct NatPreroutingStage {
    pub engine: Arc<Mutex<NatEngine>>,
}

impl Stage for NatPreroutingStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        !packet_is_decrypted(ctx)
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let iface = ctx.borrow_src_interface().to_string();
        let mut engine = self.engine.lock().await;

        // Safety: NatEngine rewrites packet header fields in-place without
        // reallocating the buffer. SlicedPacket holds &[u8] into the same
        // allocation — buffer address and length are unchanged after the write.
        let raw_mut = unsafe {
            let ptr = ctx.borrow_raw().as_ptr().cast_mut();
            std::slice::from_raw_parts_mut(ptr, ctx.borrow_raw().len())
        };

        engine.process_prerouting(raw_mut, &iface, None);
        StageOutcome::Continue
    }
}

#[derive(Clone)]
pub struct NatPostroutingStage<M: InterfaceMonitor> {
    pub engine: Arc<Mutex<NatEngine>>,
    pub routing_table: Arc<crate::netlink::routing_table::RoutingTable>,
    pub interface_monitor: Arc<M>,
}

impl<M: InterfaceMonitor> Stage for NatPostroutingStage<M> {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        !packet_is_decrypted(ctx)
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let dst_ip = match &ctx.borrow_sliced_packet().net {
            Some(NetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().destination_addr()),
            Some(NetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().destination_addr()),
            _ => return StageOutcome::Continue,
        };

        let Some(out_iface_idx) = self.routing_table.route_lookup(dst_ip) else {
            return StageOutcome::Continue;
        };

        let Some(out_iface_sys) = self.interface_monitor.get_by_index(out_iface_idx) else {
            return StageOutcome::Continue;
        };

        let mut engine = self.engine.lock().await;

        // Safety: same invariant as NatPreroutingStage.
        let raw_mut = unsafe {
            let ptr = ctx.borrow_raw().as_ptr() as *mut u8;
            std::slice::from_raw_parts_mut(ptr, ctx.borrow_raw().len())
        };

        engine.process_postrouting(raw_mut, &out_iface_sys.name, None);
        StageOutcome::Continue
    }
}

#[derive(Clone)]
pub struct FtpAlgStage {
    pub engine: Arc<Mutex<NatEngine>>,
}

impl Stage for FtpAlgStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        matches!(
            ctx.borrow_dpi_ctx(),
            Some(dpi_ctx)
                if dpi_ctx.app_proto == Some(AppProto::Ftp)
                    && !dpi_ctx.decrypted
                    && dpi_ctx.ftp_data_endpoint.is_some()
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let Some(dpi_ctx) = ctx.borrow_dpi_ctx().clone() else {
            return StageOutcome::Continue;
        };

        let original_len = ctx.borrow_raw().len();

        let mut raw_copy = ctx.borrow_raw().to_vec();

        {
            let mut engine = self.engine.lock().await;
            engine.process_ftp_alg(&mut raw_copy, &dpi_ctx);
        }

        if raw_copy.len() != original_len {
            let src_interface = ctx.borrow_src_interface().clone();
            let arrival_time = *ctx.borrow_arrival_time();
            let warnings = ctx.with_warnings_mut(std::mem::take);
            let dpi_ctx = ctx.with_dpi_ctx_mut(|dpi| dpi.take());

            match PacketContext::from_raw_full(
                raw_copy,
                src_interface,
                warnings,
                arrival_time,
                dpi_ctx,
            ) {
                Ok(new_ctx) => *ctx = new_ctx,
                Err(err) => {
                    tracing::warn!(
                        event = "ftp_alg.reparse.failed",
                        stage = "ftp_alg",
                        verdict = "drop",
                        error = %err,
                        "FTP ALG rewrite produced an invalid packet"
                    );
                    return StageOutcome::Halt;
                }
            }
        } else {
            // Safety: the backing allocation and length stay unchanged here.
            // We only overwrite bytes in-place after mutating a cloned buffer.
            unsafe {
                let ptr = ctx.borrow_raw().as_ptr().cast_mut();
                std::ptr::copy_nonoverlapping(raw_copy.as_ptr(), ptr, raw_copy.len());
            }
        }

        StageOutcome::Continue
    }
}



/// Stage sprawdzający blocklist DNS.
///
/// Aktywny wyłącznie dla pakietów DNS. Odczyt blocklist jest lock-free
/// (ArcSwap epoch load + przeszukanie trie). Blokuje pakiet przez Halt
/// jeśli domena znajduje się na liście.
#[derive(Clone)]
pub struct DnsBlockListStage {
    pub inspection: Arc<DnsInspection>,
}

impl Stage for DnsBlockListStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        matches!(
            ctx.borrow_dpi_ctx(),
            Some(dpi_ctx) if dpi_ctx.app_proto == Some(AppProto::Dns),
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let domain = match ctx.borrow_dpi_ctx() {
            Some(dpi_ctx) => dpi_ctx.dns_query_name.clone(),
            None => return StageOutcome::Continue,
        };

        let Some(domain) = domain else {
            return StageOutcome::Continue;
        };

        match self.inspection.check_blocklist(&domain) {
            BlocklistVerdict::Allow => StageOutcome::Continue,
            BlocklistVerdict::Block(msg) => {
                log_packet_decision(
                    ctx,
                    "dns.blocklist.blocked",
                    "dns_blocklist",
                    "drop",
                    &msg,
                );
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Halt
            }
        }
    }
}

/// Stage wykrywający tunelowanie DNS.
///
/// Aktywny wyłącznie dla pakietów DNS. Oblicza score podejrzenia na podstawie
/// zebranych sygnałów i wydaje werdykt samodzielnie (nie przekazuje danych do
/// PolicyEngine). Blokuje przez Halt lub dodaje ostrzeżenie w przypadku alertu.
#[derive(Clone)]
pub struct DnsTunnelingStage {
    pub inspection: Arc<DnsInspection>,
}

impl Stage for DnsTunnelingStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        matches!(
            ctx.borrow_dpi_ctx(),
            Some(dpi_ctx) if dpi_ctx.app_proto == Some(AppProto::Dns),
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let (domain, qtype) = match ctx.borrow_dpi_ctx() {
            Some(dpi_ctx) => (dpi_ctx.dns_query_name.clone(), dpi_ctx.dns_query_type),
            None => return StageOutcome::Continue,
        };

        let (Some(domain), Some(qtype)) = (domain, qtype) else {
            return StageOutcome::Continue;
        };

        match self.inspection.inspect_tunneling(&domain, &qtype) {
            DnsInspectionVerdict::Allow => StageOutcome::Continue,
            DnsInspectionVerdict::Alert(msg) => {
                log_packet_decision(
                    ctx,
                    "dns.tunneling.alert",
                    "dns_tunneling",
                    "allow_warn",
                    &msg,
                );
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Continue
            }
            DnsInspectionVerdict::Block(msg) => {
                log_packet_decision(
                    ctx,
                    "dns.tunneling.blocked",
                    "dns_tunneling",
                    "drop",
                    &msg,
                );
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Halt
            }
        }
    }
}

/// Stage mitygacji ECH w odpowiedziach DNS zawierających rekordy HTTPS/SVCB.
///
/// Aktywny wyłącznie dla odpowiedzi DNS z wykrytymi wskazówkami ECH. Przy
/// `strip_ech_dns` blokuje odpowiedź przez Halt, w przeciwnym razie emituje
/// jedynie zdarzenie audytowe.
#[derive(Clone)]
pub struct DnsEchMitigationStage {
    pub inspection: Arc<DnsInspection>,
}

impl Stage for DnsEchMitigationStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        matches!(
            ctx.borrow_dpi_ctx(),
            Some(dpi_ctx)
                if dpi_ctx.app_proto == Some(AppProto::Dns)
                    && dpi_ctx.dns_is_response == Some(true)
                    && dpi_ctx.dns_has_ech_hints,
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let domain = match ctx.borrow_dpi_ctx() {
            Some(dpi_ctx) => dpi_ctx.dns_query_name.clone(),
            None => return StageOutcome::Continue,
        };

        let Some(domain) = domain else {
            return StageOutcome::Continue;
        };

        match self.inspection.inspect_ech(&domain, true) {
            EchMitigationVerdict::Allow => StageOutcome::Continue,
            EchMitigationVerdict::Block(msg) => {
                tracing::debug!(reason = %msg, "DNS ECH mitigation block");
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Halt
            }
        }
    }
}

#[derive(Clone)]
pub struct IpsStage {
    pub inspection: Arc<Ips>,
}

impl Stage for IpsStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        use etherparse::TransportSlice;

        matches!(
            &ctx.borrow_sliced_packet().transport,
            Some(TransportSlice::Tcp(_) | TransportSlice::Udp(_))
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        ctx.with_dpi_ctx_mut(|dpi| {
            if let Some(dpi) = dpi.as_mut() {
                dpi.ips_match = None;
            }
        });

        match self.inspection.inspect_packet(ctx) {
            IpsVerdict::Allow => StageOutcome::Continue,
            IpsVerdict::Alert(matches) => {
                let msg = matches
                    .iter()
                    .map(IpsSignatureMatch::message)
                    .collect::<Vec<_>>()
                    .join("; ");
                ctx.with_dpi_ctx_mut(|dpi| {
                    if let Some(dpi) = dpi.as_mut() {
                        let first = matches.first().expect("alert matches should not be empty");
                        dpi.ips_match = Some(crate::dpi::IpsMatch {
                            signature_name: first.name.clone(),
                            severity: first.severity.as_str().to_string(),
                            blocked: false,
                        });
                    }
                });
                for matched in matches {
                    emit_ips_signature_matched(ctx, &matched);
                }
                log_packet_decision(ctx, "ips.signature.alert", "ips", "allow_warn", &msg);
                ctx.with_warnings_mut(|warnings| warnings.push(msg));
                StageOutcome::Continue
            }
            IpsVerdict::Block(matched) => {
                let msg = matched.message();
                ctx.with_dpi_ctx_mut(|dpi| {
                    if let Some(dpi) = dpi.as_mut() {
                        dpi.ips_match = Some(crate::dpi::IpsMatch {
                            signature_name: matched.name.clone(),
                            severity: matched.severity.as_str().to_string(),
                            blocked: true,
                        });
                    }
                });
                emit_ips_signature_matched(ctx, &matched);
                log_packet_decision(ctx, "ips.signature.blocked", "ips", "drop", &msg);
                ctx.with_warnings_mut(|warnings| warnings.push(msg));
                StageOutcome::Halt
            }
        }
    }
}

fn emit_ips_signature_matched(ctx: &PacketContext, matched: &IpsSignatureMatch) {
    let sliced_packet = ctx.borrow_sliced_packet();

    let (src_ip, dst_ip) = match &sliced_packet.net {
        Some(NetSlice::Ipv4(ipv4)) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
        ),
        Some(NetSlice::Ipv6(ipv6)) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
        ),
        _ => return,
    };

    let (src_port, dst_port, transport_protocol, payload_length) = match &sliced_packet.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => (
            tcp.source_port(),
            tcp.destination_port(),
            "tcp",
            tcp.payload().len(),
        ),
        Some(etherparse::TransportSlice::Udp(udp)) => (
            udp.source_port(),
            udp.destination_port(),
            "udp",
            udp.payload().len(),
        ),
        _ => return,
    };

    let app_protocol = ctx
        .borrow_dpi_ctx()
        .as_ref()
        .and_then(|dpi_ctx| dpi_ctx.app_proto)
        .map(|proto| proto.to_string().to_lowercase())
        .unwrap_or_default();

    events::emit(Event::new(EventKind::IpsSignatureMatched {
        signature_id: matched.id.clone(),
        signature_name: matched.name.clone(),
        category: matched.category.clone(),
        severity: matched.severity.as_str().to_string(),
        action: matched.action.as_str().to_string(),
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        transport_protocol: transport_protocol.to_string(),
        app_protocol,
        interface: ctx.borrow_src_interface().to_string(),
        payload_length: u32::try_from(payload_length).unwrap_or(u32::MAX),
    }));
}

fn emit_ml_threat_detected(ctx: &PacketContext, prediction: &MlPrediction) {
    let fields = packet_log_fields(ctx);
    let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port)) = (
        fields.src_ip,
        fields.dst_ip,
        fields.src_port,
        fields.dst_port,
    ) else {
        return;
    };

    events::emit(Event::new(EventKind::MlThreatDetected {
        score: prediction.malicious_score,
        threshold: prediction.threshold,
        model_checksum: prediction.model_checksum.clone(),
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        transport_protocol: fields.protocol.unwrap_or("").to_string(),
        app_protocol: fields.app_proto.unwrap_or_default(),
        interface: ctx.borrow_src_interface().to_string(),
        payload_length: u32::try_from(fields.payload_length).unwrap_or(u32::MAX),
    }));
}

/// Stage ewaluacji polityk.
///
/// Opcjonalnie przyjmuje dostawcę DNSSEC (`dnssec`) — jeśli jest obecny,
/// dla pakietów DNS wywołuje walidację DNSSEC w `spawn_blocking` (blokujące I/O
/// sieciowe nie może odbywać się bezpośrednio w kontekście async).
#[derive(Clone)]
pub struct PolicyEvalStage {
    pub provider: Arc<DiskPolicyProvider>,
    /// Opcjonalny dostawca DNSSEC — wstrzykiwany z `DnsInspection`.
    pub dnssec: Option<Arc<dyn DnssecProvider>>,
}

impl Stage for PolicyEvalStage {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let arrival = ArrivalInfo::from_time(ctx.borrow_arrival_time());

        // Wyznacz status DNSSEC dla pakietów DNS (leniwie, przez spawn_blocking).
        let dnssec_status = if let Some(provider) = &self.dnssec {
            let is_dns = ctx
                .borrow_dpi_ctx()
                .as_ref()
                .map_or(false, |d| d.app_proto == Some(AppProto::Dns));

            if is_dns {
                let domain = ctx
                    .borrow_dpi_ctx()
                    .as_ref()
                    .and_then(|d| d.dns_query_name.clone());
                let qtype = ctx.borrow_dpi_ctx().as_ref().and_then(|d| d.dns_query_type);

                if let Some(domain) = domain {
                    let p = Arc::clone(provider);
                    tokio::task::spawn_blocking(move || p.check_domain(&domain, qtype).status)
                        .await
                        .ok()
                        .map(Some)
                        .unwrap_or(None)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let dns_ctx = dnssec_status.map(|status| DnsEvalContext {
            dnssec_status: Some(status),
        });

        let verdict = self.provider.get_evaluator().evaluate(PolicyEvalContext {
            packet: ctx.borrow_sliced_packet(),
            arrival: &arrival,
            dns: dns_ctx.as_ref(),
            dpi: ctx.borrow_dpi_ctx().as_ref(),
        });

        match verdict {
            Verdict::Allow => StageOutcome::Continue,
            Verdict::Drop => {
                log_packet_decision(
                    ctx,
                    "policy.packet.dropped",
                    "policy_eval",
                    "drop",
                    "policy returned drop verdict",
                );
                StageOutcome::Halt
            }
            Verdict::AllowWarn(msg) => {
                log_packet_decision(
                    ctx,
                    "policy.packet.allowed_with_warning",
                    "policy_eval",
                    "allow_warn",
                    &msg,
                );
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Continue
            }
            Verdict::DropWarn(msg) => {
                log_packet_decision(
                    ctx,
                    "policy.packet.dropped_with_warning",
                    "policy_eval",
                    "drop_warn",
                    &msg,
                );
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Halt
            }
        }
    }
}

#[derive(Clone)]
pub struct TcpClassificationStage {
    pub tracker: Arc<TcpSessionTracker>,
    pub flow_stats: Arc<crate::ml::FlowStatsAggregator>,
}

impl Stage for TcpClassificationStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        !packet_is_decrypted(ctx)
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        // ML features z TCP header + rolling flow stats per src_ip.
        populate_ml_tcp_and_flow_stats(ctx, &self.flow_stats);

        match self.tracker.process_packet(ctx.borrow_sliced_packet()) {
            Ok(_) => StageOutcome::Continue,
            Err(e) => {
                log_packet_decision(
                    ctx,
                    "tcp_session.tracking.failed",
                    "tcp_classification",
                    "drop",
                    &e.to_string(),
                );
                StageOutcome::Halt
            }
        }
    }
}

fn populate_ml_tcp_and_flow_stats(
    ctx: &mut PacketContext,
    flow_stats: &crate::ml::FlowStatsAggregator,
) {
    use std::time::Instant;

    // Jedna sesja borrow'u: wyciągnij wszystkie potrzebne dane z `sliced`
    // zanim zaczniesz mutować `ml_feature_vector` (ouroboros accessors są
    // rozłączne, ale żeby trzymać to czytelne — kopia do lokalnych).
    struct TcpSnap {
        syn: bool,
        ack: bool,
        fin: bool,
        rst: bool,
        psh: bool,
        window: u16,
    }
    let (tcp_snap, src_ip, dst_ip) = {
        let sliced = ctx.borrow_sliced_packet();
        let tcp_snap = if let Some(TransportSlice::Tcp(tcp)) = &sliced.transport {
            Some(TcpSnap {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
                psh: tcp.psh(),
                window: tcp.window_size(),
            })
        } else {
            None
        };
        let (src_ip, dst_ip) = match &sliced.net {
            Some(NetSlice::Ipv4(ipv4)) => (
                Some(IpAddr::V4(ipv4.header().source_addr())),
                Some(IpAddr::V4(ipv4.header().destination_addr())),
            ),
            Some(NetSlice::Ipv6(ipv6)) => (
                Some(IpAddr::V6(ipv6.header().source_addr())),
                Some(IpAddr::V6(ipv6.header().destination_addr())),
            ),
            _ => (None, None),
        };
        (tcp_snap, src_ip, dst_ip)
    };

    let is_syn = tcp_snap.as_ref().map(|t| t.syn && !t.ack).unwrap_or(false);
    let is_new_flow = is_syn;
    let now = Instant::now();

    if let (Some(src), Some(dst)) = (src_ip, dst_ip) {
        flow_stats.observe_packet(src, dst, is_syn, is_new_flow, now);
    }

    let iat = src_ip
        .map(|src| flow_stats.iat_since_last(src, now))
        .unwrap_or_default();
    let snapshot = src_ip
        .map(|src| flow_stats.snapshot(src, now))
        .unwrap_or_default();

    ctx.with_ml_feature_vector_mut(|mlv| {
        if let Some(snap) = &tcp_snap {
            mlv.tcp_syn = snap.syn;
            mlv.tcp_ack = snap.ack;
            mlv.tcp_fin = snap.fin;
            mlv.tcp_rst = snap.rst;
            mlv.tcp_psh = snap.psh;
            mlv.tcp_window_log = (1.0 + snap.window as f32).ln();
        }
        mlv.set_flow_snapshot(&snapshot, iat);
    });
}

#[derive(Clone)]
pub struct MlAlertStage {
    pub detector: Arc<dyn MlPacketInspector>,
    cooldown: Duration,
    last_alert: Arc<DashMap<FlowKey, Instant>>,
}

impl MlAlertStage {
    pub fn new(detector: Arc<dyn MlPacketInspector>) -> Self {
        Self {
            detector,
            cooldown: Duration::from_secs(10),
            last_alert: Arc::new(DashMap::new()),
        }
    }

    fn should_emit(&self, ctx: &PacketContext) -> bool {
        let Some(key) = packet_flow_key(ctx) else {
            return true;
        };
        let now = Instant::now();

        if let Some(mut last_seen) = self.last_alert.get_mut(&key) {
            if now.duration_since(*last_seen) < self.cooldown {
                return false;
            }
            *last_seen = now;
            return true;
        }

        self.last_alert.insert(key, now);
        true
    }
}

impl Stage for MlAlertStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        self.detector.is_enabled()
            && matches!(
                &ctx.borrow_sliced_packet().transport,
                Some(TransportSlice::Tcp(_) | TransportSlice::Udp(_))
            )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let features = ctx.borrow_ml_feature_vector().to_f32_array();

        match self.detector.inspect_features(features) {
            Ok(Some(prediction)) if self.should_emit(ctx) => {
                let msg = ml_alert_message(&prediction);
                emit_ml_threat_detected(ctx, &prediction);
                log_packet_decision(ctx, "ml.threat.alert", "ml", "allow_warn", &msg);
                ctx.with_warnings_mut(|warnings| warnings.push(msg));
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(
                    event = "ml.inference.failed",
                    error = %err,
                    "ML inference failed"
                );
            }
        }

        StageOutcome::Continue
    }
}

fn ml_alert_message(prediction: &MlPrediction) -> String {
    format!(
        "ML threat score {:.4} exceeded threshold {:.4}",
        prediction.malicious_score, prediction.threshold
    )
}

#[derive(Clone)]
pub struct DpiStage {
    pub classifier: Arc<DpiClassifier>,
    pub flow_stats: Arc<crate::ml::FlowStatsAggregator>,
    pub pinning_detector: Option<Arc<crate::tls::pinning_detector::PinningDetector>>,
}

impl Stage for DpiStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        use etherparse::TransportSlice;

        matches!(
            &ctx.borrow_sliced_packet().transport,
            Some(TransportSlice::Tcp(_) | TransportSlice::Udp(_))
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        match self.classifier.inspect_packet(ctx.borrow_sliced_packet()) {
            InspectResult::Done(mut dpi_ctx) => {
                merge_preserved_dpi_fields(ctx.borrow_dpi_ctx().as_ref(), &mut dpi_ctx);
                tracing::debug!(
                    event = "dpi.classification.completed",
                    stage = "dpi",
                    app_proto = ?dpi_ctx.app_proto,
                    "DPI classification completed"
                );
                // Rejestruj DNS response w aggregatorze (dla nxdomain_ratio).
                if dpi_ctx.app_proto == Some(AppProto::Dns)
                    && dpi_ctx.dns_is_response == Some(true)
                {
                    let src_ip = match &ctx.borrow_sliced_packet().net {
                        Some(NetSlice::Ipv4(ipv4)) => {
                            Some(IpAddr::V4(ipv4.header().source_addr()))
                        }
                        Some(NetSlice::Ipv6(ipv6)) => {
                            Some(IpAddr::V6(ipv6.header().source_addr()))
                        }
                        _ => None,
                    };
                    if let Some(src) = src_ip {
                        self.flow_stats.observe_dns_response(
                            src,
                            dpi_ctx.dns_rcode,
                            std::time::Instant::now(),
                        );
                    }
                }
                // Pinning failures: potrzebne src_ip + SNI.
                let pinning_failures = match (
                    self.pinning_detector.as_ref(),
                    dpi_ctx.tls_sni.as_deref(),
                ) {
                    (Some(det), Some(sni)) => {
                        let src_ip = match &ctx.borrow_sliced_packet().net {
                            Some(NetSlice::Ipv4(ipv4)) => {
                                Some(IpAddr::V4(ipv4.header().source_addr()))
                            }
                            Some(NetSlice::Ipv6(ipv6)) => {
                                Some(IpAddr::V6(ipv6.header().source_addr()))
                            }
                            _ => None,
                        };
                        src_ip.map(|ip| det.failure_count_for(ip, sni)).unwrap_or(0)
                    }
                    _ => 0,
                };
                ctx.with_ml_feature_vector_mut(|mlv| {
                    mlv.set_from_dpi(&dpi_ctx);
                    mlv.set_pinning_failures(pinning_failures);
                });
                ctx.with_dpi_ctx_mut(|c| *c = Some(dpi_ctx));
            }
            InspectResult::NeedMore => {}
            InspectResult::Skipped => {}
        }
        StageOutcome::Continue
    }
}

#[derive(Clone)]
pub struct TlsPortEnforcementStage {
    pub config_provider: Arc<AppConfigProvider>,
}

impl Stage for TlsPortEnforcementStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        matches!(
            ctx.borrow_dpi_ctx(),
            Some(dpi_ctx)
                if dpi_ctx.app_proto == Some(AppProto::Tls) && !dpi_ctx.decrypted
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let config = self.config_provider.get_config();

        let dst_port = match &ctx.borrow_sliced_packet().transport {
            Some(TransportSlice::Tcp(tcp)) => tcp.destination_port(),
            _ => return StageOutcome::Continue,
        };

        if !tls_port_enforcement_blocks(&config, dst_port) {
            return StageOutcome::Continue;
        }

        let msg = format!("TLS detected on undeclared port {dst_port}");
        tracing::debug!(dst_port, "TLS enforcement block");
        ctx.with_warnings_mut(|w| w.push(msg));
        StageOutcome::Halt
    }
}

fn tls_port_enforcement_blocks(config: &AppConfig, dst_port: u16) -> bool {
    config.block_tls_on_undeclared_ports && !config.tls_inspection_ports.contains(&dst_port)
}

fn merge_preserved_dpi_fields(existing: Option<&crate::dpi::DpiContext>, next: &mut crate::dpi::DpiContext) {
    let Some(existing) = existing else {
        return;
    };

    next.decrypted |= existing.decrypted;
    next.src_port = next.src_port.or(existing.src_port);
    next.dst_port = next.dst_port.or(existing.dst_port);
}

fn log_packet_decision(
    ctx: &PacketContext,
    event: &'static str,
    stage: &'static str,
    verdict: &'static str,
    reason: &str,
) {
    let fields = packet_log_fields(ctx);

    tracing::warn!(
        event,
        stage,
        verdict,
        reason,
        iface = %ctx.borrow_src_interface(),
        packet_len = fields.packet_len,
        src_ip = fields.src_ip.as_deref().unwrap_or(""),
        dst_ip = fields.dst_ip.as_deref().unwrap_or(""),
        src_port = fields.src_port.unwrap_or_default(),
        dst_port = fields.dst_port.unwrap_or_default(),
        protocol = fields.protocol.unwrap_or(""),
        app_proto = fields.app_proto.as_deref().unwrap_or(""),
        "packet decision"
    );
}

struct PacketLogFields {
    packet_len: usize,
    payload_length: usize,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Option<&'static str>,
    app_proto: Option<String>,
}

fn packet_log_fields(ctx: &PacketContext) -> PacketLogFields {
    let sliced = ctx.borrow_sliced_packet();
    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => (
            Some(ipv4.header().source_addr().to_string()),
            Some(ipv4.header().destination_addr().to_string()),
        ),
        Some(NetSlice::Ipv6(ipv6)) => (
            Some(ipv6.header().source_addr().to_string()),
            Some(ipv6.header().destination_addr().to_string()),
        ),
        _ => (None, None),
    };

    let (src_port, dst_port, protocol, payload_length) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (
            Some(tcp.source_port()),
            Some(tcp.destination_port()),
            Some("tcp"),
            tcp.payload().len(),
        ),
        Some(TransportSlice::Udp(udp)) => (
            Some(udp.source_port()),
            Some(udp.destination_port()),
            Some("udp"),
            udp.payload().len(),
        ),
        Some(TransportSlice::Icmpv4(_)) => (None, None, Some("icmpv4"), 0),
        Some(TransportSlice::Icmpv6(_)) => (None, None, Some("icmpv6"), 0),
        _ => (None, None, None, 0),
    };

    let app_proto = ctx
        .borrow_dpi_ctx()
        .as_ref()
        .and_then(|dpi_ctx| dpi_ctx.app_proto)
        .map(|proto| proto.to_string().to_lowercase());

    PacketLogFields {
        packet_len: ctx.borrow_raw().len(),
        payload_length,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        app_proto,
    }
}

fn packet_flow_key(ctx: &PacketContext) -> Option<FlowKey> {
    let sliced = ctx.borrow_sliced_packet();
    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => (
            IpAddr::V4(ipv4.header().source_addr()),
            IpAddr::V4(ipv4.header().destination_addr()),
        ),
        Some(NetSlice::Ipv6(ipv6)) => (
            IpAddr::V6(ipv6.header().source_addr()),
            IpAddr::V6(ipv6.header().destination_addr()),
        ),
        _ => return None,
    };
    let (src_port, dst_port) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port()),
        Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port()),
        _ => return None,
    };

    Some(FlowKey::new(src_ip, src_port, dst_ip, dst_port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::path::PathBuf;

    fn sample_config() -> AppConfig {
        AppConfig {
            capture_interfaces: vec!["eth1".into(), "eth2".into()],
            pcap_timeout_ms: 5000,
            tun_device_name: "tun0".into(),
            tun_address: "10.254.254.1".parse().unwrap(),
            tun_netmask: "255.255.255.0".parse().unwrap(),
            data_dir: PathBuf::from("/tmp"),
            event_socket_path: "/tmp/event.sock".into(),
            query_socket_path: "/tmp/query.sock".into(),
            dev_config: None,
            pki_dir: "/tmp/pki".into(),
            ssl_inspection_enabled: true,
            mitm_listen_addr: "127.0.0.1:8443".into(),
            control_plane_socket_path: "/tmp/control.sock".into(),
            server_cert_socket_path: "/tmp/server-cert.sock".into(),
            ssl_bypass_domains: Vec::new(),
            tls_inspection_ports: vec![443],
            block_tls_on_undeclared_ports: false,
        }
    }

    fn tcp_context(src: [u8; 4], dst: [u8; 4], dst_port: u16, iface: &str) -> PacketContext {
        let mut raw = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4(src, dst, 64)
            .tcp(12345, dst_port, 1, 65535)
            .write(&mut raw, b"hello")
            .unwrap();

        PacketContext::from_raw(raw, Arc::from(iface)).unwrap()
    }

    #[test]
    fn packet_destination_ip_extracts_ipv4_destination() {
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth1");
        assert_eq!(
            packet_destination_ip(&ctx),
            Some("192.168.20.10".parse().unwrap())
        );
    }

    #[test]
    fn tls_redirect_halts_tcp_443_on_capture_interface() {
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth1");
        assert!(should_halt_for_tls_redirect(&ctx, &sample_config()));
    }

    #[test]
    fn tls_redirect_ignores_non_tls_ports() {
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 80, "eth1");
        assert!(!should_halt_for_tls_redirect(&ctx, &sample_config()));
    }

    #[test]
    fn tls_redirect_ignores_unknown_interfaces() {
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth9");
        assert!(!should_halt_for_tls_redirect(&ctx, &sample_config()));
    }

    #[test]
    fn tls_redirect_halts_on_custom_inspection_port() {
        let mut config = sample_config();
        config.tls_inspection_ports = vec![443, 8443];
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 8443, "eth1");
        assert!(should_halt_for_tls_redirect(&ctx, &config));
    }

    #[test]
    fn tls_redirect_ignores_port_outside_inspection_list() {
        let mut config = sample_config();
        config.tls_inspection_ports = vec![443];
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 8443, "eth1");
        assert!(!should_halt_for_tls_redirect(&ctx, &config));
    }

    #[test]
    fn tls_port_enforcement_passes_when_flag_off() {
        let mut config = sample_config();
        config.block_tls_on_undeclared_ports = false;
        config.tls_inspection_ports = vec![443];
        assert!(!tls_port_enforcement_blocks(&config, 8443));
    }

    #[test]
    fn tls_port_enforcement_blocks_undeclared_port_when_flag_on() {
        let mut config = sample_config();
        config.block_tls_on_undeclared_ports = true;
        config.tls_inspection_ports = vec![443];
        assert!(tls_port_enforcement_blocks(&config, 8443));
    }

    #[test]
    fn tls_port_enforcement_allows_declared_port_when_flag_on() {
        let mut config = sample_config();
        config.block_tls_on_undeclared_ports = true;
        config.tls_inspection_ports = vec![443, 8443];
        assert!(!tls_port_enforcement_blocks(&config, 8443));
    }

    #[test]
    fn packet_is_decrypted_detects_seeded_tls_plaintext_context() {
        let mut ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth1");
        ctx.with_dpi_ctx_mut(|dpi| {
            *dpi = Some(crate::dpi::DpiContext {
                decrypted: true,
                src_port: Some(12345),
                dst_port: Some(443),
                ..Default::default()
            });
        });

        assert!(packet_is_decrypted(&ctx));
    }

    #[test]
    fn merge_preserved_dpi_fields_keeps_decrypted_metadata() {
        let existing = crate::dpi::DpiContext {
            decrypted: true,
            src_port: Some(12345),
            dst_port: Some(443),
            ..Default::default()
        };
        let mut classified = crate::dpi::DpiContext {
            app_proto: Some(crate::dpi::AppProto::Http),
            ..Default::default()
        };

        merge_preserved_dpi_fields(Some(&existing), &mut classified);

        assert!(classified.decrypted);
        assert_eq!(classified.src_port, Some(12345));
        assert_eq!(classified.dst_port, Some(443));
        assert_eq!(classified.app_proto, Some(crate::dpi::AppProto::Http));
    }

    struct StaticMlInspector;

    impl MlPacketInspector for StaticMlInspector {
        fn inspect_features(&self, _features: [f32; 38]) -> anyhow::Result<Option<MlPrediction>> {
            Ok(Some(MlPrediction {
                malicious_score: 0.91,
                threshold: 0.2,
                model_checksum: "test".to_string(),
            }))
        }

        fn is_enabled(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn ml_alert_stage_warns_and_continues() {
        let detector: Arc<dyn MlPacketInspector> = Arc::new(StaticMlInspector);
        let stage = MlAlertStage::new(detector);
        let mut ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 80, "eth1");

        let outcome = stage.process(&mut ctx).await;

        assert!(matches!(outcome, StageOutcome::Continue));
        assert_eq!(ctx.borrow_warnings().len(), 1);
        assert!(ctx.borrow_warnings()[0].contains("ML threat score"));
    }

    #[tokio::test]
    async fn ml_alert_stage_cooldown_suppresses_repeated_flow_warning() {
        let detector: Arc<dyn MlPacketInspector> = Arc::new(StaticMlInspector);
        let stage = MlAlertStage::new(detector);
        let mut ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 80, "eth1");

        assert!(matches!(stage.process(&mut ctx).await, StageOutcome::Continue));
        assert!(matches!(stage.process(&mut ctx).await, StageOutcome::Continue));

        assert_eq!(ctx.borrow_warnings().len(), 1);
    }
}
