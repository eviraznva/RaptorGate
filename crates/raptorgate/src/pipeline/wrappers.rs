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
        packet_context::PacketContext,
        tcp_session_tracker::TcpSessionTracker,
    },
    nat::NatEngine,
    dpi::{DpiClassifier, FlowKey, InspectResult},
    events::{self, Event, EventKind},
    metrics::MetricsCollector,
    ml::{MlPacketInspector, MlPrediction},
    packet_validator::validate,
    pipeline::{Stage, StageOutcome},
    policy::engine::PolicyEngine,
    rule_tree::{ArrivalInfo, Verdict},
    zones::{
        provider::ZoneInterfaceProvider, InterfaceStatus, PhysicalInterface, VlanSubinterface,
        ZoneId, ZoneInterface, ZoneInterfaceId, ZoneInterfaceKind, ZonePairId,
    },
};
use crate::conntrack::table::{Conntrack, ProcessOutcome};
use crate::conntrack::tuple::Direction;
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
pub struct MetricsStage {
    pub collector: Arc<MetricsCollector>,
}

impl Stage for MetricsStage {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        self.collector.observe_packet(ctx.borrow_raw().len());
        StageOutcome::Continue
    }
}

#[derive(Clone)]
pub struct LocalOwnershipStage {
    pub config_provider: Arc<AppConfigProvider>,
    pub zone_interface_provider: Arc<ZoneInterfaceProvider>,
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
        if should_halt_for_tls_redirect(ctx, &config, &self.zone_interface_provider) {
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

fn should_halt_for_tls_redirect(
    ctx: &PacketContext,
    config: &AppConfig,
    zone_interface_provider: &ZoneInterfaceProvider,
) -> bool {
    if !config.ssl_inspection_enabled {
        return false;
    }
    if !zone_interface_provider
        .get_zone_interface_by_name(ctx.borrow_src_interface().as_ref())
        .is_some_and(|(_, zi)| zi.sniffed)
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
    pub engine: Arc<NatEngine>,
}

impl Stage for NatPreroutingStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        !packet_is_decrypted(ctx) && ctx.ct().is_some()
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let Some(ct) = ctx.ct().cloned() else { return StageOutcome::Continue; };
        let info = ctx.ct_info().unwrap_or(crate::conntrack::entry::CtInfo::Established);
        let iface = ctx.borrow_src_interface().to_string();

        // Safety: NatEngine rewrites packet header fields in-place without
        // reallocating the buffer.
        let raw_mut = unsafe {
            let ptr = ctx.borrow_raw().as_ptr().cast_mut();
            std::slice::from_raw_parts_mut(ptr, ctx.borrow_raw().len())
        };

        let _ = self.engine.prerouting(raw_mut, &ct, info, &iface, None);
        StageOutcome::Continue
    }
}

#[derive(Clone)]
pub struct NatPostroutingStage<M: InterfaceMonitor> {
    pub engine: Arc<NatEngine>,
    pub routing_table: Arc<crate::netlink::routing_table::RoutingTable>,
    pub interface_monitor: Arc<M>,
}

impl<M: InterfaceMonitor> Stage for NatPostroutingStage<M> {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        !packet_is_decrypted(ctx) && ctx.ct().is_some()
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let Some(ct) = ctx.ct().cloned() else { return StageOutcome::Continue; };
        let info = ctx.ct_info().unwrap_or(crate::conntrack::entry::CtInfo::Established);

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

        ct.record_egress_interface(
            ctx.ct_direction().unwrap_or(Direction::Original),
            &out_iface_sys.name,
        );

        let raw_mut = unsafe {
            let ptr = ctx.borrow_raw().as_ptr() as *mut u8;
            std::slice::from_raw_parts_mut(ptr, ctx.borrow_raw().len())
        };

        let _ = self.engine.postrouting(raw_mut, &ct, info, &out_iface_sys.name, None);
        StageOutcome::Continue
    }
}

#[derive(Clone)]
pub struct FtpAlgStage {
    pub conntrack: Arc<Conntrack>,
    pub helpers: Arc<crate::conntrack::helper::HelperRegistry>,
}

impl Stage for FtpAlgStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        ctx.ct().is_some() && matches!(ctx.borrow_dpi_ctx(), Some(dpi_ctx) if dpi_ctx.app_proto == Some(AppProto::Ftp) && !dpi_ctx.decrypted)
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let Some(ct) = ctx.ct().cloned() else { return StageOutcome::Continue; };

        let Some(dpi_ctx) = ctx.borrow_dpi_ctx().clone() else {
            return StageOutcome::Continue;
        };

        // 1. Payload rewrite — tylko gdy DPI rozpoznał komendę PORT/PASV/EPRT/EPSV.
        if dpi_ctx.ftp_data_endpoint.is_some() {
            let original_len = ctx.borrow_raw().len();
            let mut raw_copy = ctx.borrow_raw().to_vec();

            match crate::nat::alg::ftp::ftp_alg_rewrite(&mut raw_copy, &dpi_ctx) {
                Ok(true) => {
                    if raw_copy.len() != original_len {
                        let src_interface = ctx.borrow_src_interface().clone();
                        let arrival_time = *ctx.borrow_arrival_time();
                        let warnings = ctx.with_warnings_mut(std::mem::take);
                        let dpi_ctx_taken = ctx.with_dpi_ctx_mut(|dpi| dpi.take());

                        match PacketContext::from_raw_full(
                            raw_copy,
                            src_interface,
                            warnings,
                            arrival_time,
                            dpi_ctx_taken,
                        ) {
                            Ok(new_ctx) => *ctx = new_ctx,
                            Err(err) => {
                                tracing::warn!(
                                    event = "ftp_alg.reparse.failed",
                                    error = %err,
                                    "FTP ALG rewrite produced an invalid packet"
                                );
                                return StageOutcome::Halt;
                            }
                        }
                    } else {
                        unsafe {
                            let ptr = ctx.borrow_raw().as_ptr().cast_mut();
                            std::ptr::copy_nonoverlapping(raw_copy.as_ptr(), ptr, raw_copy.len());
                        }
                    }
                }
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!(error = %err, "ftp alg rewrite failed");
                    return StageOutcome::Halt;
                }
            }
        }

        // 2. Helper dispatch — instalacja expectations dla data channel.
        let key_proto = ct.original.protocol;
        let key_port = ct.original.dst_port;

        if let Some(helper) = self.helpers.lookup(key_proto, key_port) {
            let dir = ctx.ct_direction().unwrap_or(crate::conntrack::tuple::Direction::Original);
            let payload = transport_payload_slice(ctx.borrow_raw());
            
            helper.install_expectations(&ct, payload, dir, &self.conntrack);
        }

        StageOutcome::Continue
    }
}

fn transport_payload_slice(raw: &[u8]) -> &[u8] {
    match crate::nat::packet::transport_payload_range(raw) {
        Some(range) => &raw[range],
        None => &[],
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
        attack_type: prediction.attack_type.clone(),
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
pub struct PolicyEvalStage<ZR> where ZR: crate::zones::resolver::ZoneResolver {
    pub policy_engine: Arc<PolicyEngine>,
    pub zone_resolver: Arc<ZR>,
    /// Opcjonalny dostawca DNSSEC — wstrzykiwany z `DnsInspection`.
    pub dnssec: Option<Arc<dyn DnssecProvider>>,
}

impl<ZR> Stage for PolicyEvalStage<ZR> where ZR: crate::zones::resolver::ZoneResolver {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let arrival = ArrivalInfo::from_time(ctx.borrow_arrival_time());

        let dst_ip = match &ctx.borrow_sliced_packet().net {
            Some(NetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().destination_addr()),
            Some(NetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().destination_addr()),
            _ => return StageOutcome::Continue,
        };

        let pair = self.zone_resolver.resolve(ctx.borrow_src_interface(), dst_ip);
        
        let pair_id = match pair {
            Some(ref p) => &p.id,
            None => {
                // DEV: brak zone pair = allow zamiast drop. Permanentny fix wymaga
                // konfiguracji zones.json + zone_pairs.json + zone_interfaces.json.
                tracing::warn!(
                    event = "policy.zone_pair.missing",
                    iface = %ctx.borrow_src_interface(),
                    dst_ip = %dst_ip,
                    "no matching zone pair, allowing (dev fallback)"
                );
                return StageOutcome::Continue;
            }
        };

        let dnssec_status = if let Some(provider) = &self.dnssec {
            let is_dns = ctx
                .borrow_dpi_ctx()
                .as_ref()
                .is_some_and(|d| d.app_proto == Some(AppProto::Dns));

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

        let verdict = self.policy_engine.evaluate(pair_id, PolicyEvalContext {
            packet: ctx.borrow_sliced_packet(),
            arrival: &arrival,
            dns: dns_ctx.as_ref(),
            dpi: ctx.borrow_dpi_ctx().as_ref(),
        });

        match verdict {
            Some(Verdict::Allow) => StageOutcome::Continue,
            Some(Verdict::Drop) => {
                log_packet_decision(
                    ctx,
                    "policy.packet.dropped",
                    "policy_eval",
                    "drop",
                    "policy returned drop verdict",
                );
                StageOutcome::Halt
            }
            Some(Verdict::AllowWarn(msg)) => {
                log_packet_decision(
                    ctx,
                    "policy.packet.allowed_with_warning",
                    "policy_eval",
                    "allow_warn",
                    &msg,
                );
                ctx.with_warnings_mut(|w| w.push(msg.clone()));
                events::emit(Event::new(EventKind::PolicyWarning { message: msg, verdict: "allow" }));
                StageOutcome::Continue
            }
            Some(Verdict::DropWarn(msg)) => {
                log_packet_decision(
                    ctx,
                    "policy.packet.dropped_with_warning",
                    "policy_eval",
                    "drop_warn",
                    &msg,
                );
                ctx.with_warnings_mut(|w| w.push(msg.clone()));
                events::emit(Event::new(EventKind::PolicyWarning { message: msg, verdict: "drop" }));
                StageOutcome::Halt
            }
            None => {
                let fallback = pair.map(|p| p.default_policy).unwrap_or(crate::zones::DefaultPolicy::Drop);
                match fallback {
                    crate::zones::DefaultPolicy::Allow => StageOutcome::Continue,
                    _ => {
                        log_packet_decision(
                            ctx,
                            "policy.packet.dropped",
                            "policy_eval",
                            "drop",
                            "no policy or default drop",
                        );
                        StageOutcome::Halt
                    }
                }
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
        "ML threat {} score {:.4} exceeded threshold {:.4}",
        prediction.attack_type, prediction.malicious_score, prediction.threshold
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

#[derive(Clone)]
pub struct ConntrackInStage {
    pub ct: Arc<Conntrack>,
}

impl Stage for ConntrackInStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        !packet_is_decrypted(ctx)
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let outcome = self.ct.process(ctx.borrow_sliced_packet(), 0);

        match outcome {
            ProcessOutcome::Accept { entry, info, direction, is_new } => {
                entry.record_ingress_interface(direction, ctx.borrow_src_interface().as_ref());
                ctx.set_conntrack(entry, info, direction, is_new);

                if is_new {
                    tracing::info!(
                        event = "conntrack.flow.new",
                        proto = ?ctx.ct().unwrap().original.protocol,
                        info = ?info,
                        dir = ?direction,
                        flow_id = ctx.ct().unwrap().id,
                        "new flow"
                    );
                } else {
                    tracing::debug!(
                        event = "conntrack.lookup.hit",
                        proto = ?ctx.ct().unwrap().original.protocol,
                        info = ?info,
                        dir = ?direction,
                        flow_id = ctx.ct().unwrap().id,
                        "existing flow"
                    );
                }

                StageOutcome::Continue
            }
            ProcessOutcome::Invalid => {
                log_packet_decision(ctx, "conntrack.invalid", "conntrack_in", "drop", "invalid packet");
                StageOutcome::Halt
            }
            ProcessOutcome::Drop => {
                log_packet_decision(ctx, "conntrack.drop", "conntrack_in", "drop", "ct verdict drop");
                StageOutcome::Halt
            }
            ProcessOutcome::TableFull => {
                log_packet_decision(ctx, "conntrack.table_full", "conntrack_in", "drop", "max_entries");
                StageOutcome::Halt
            }
        }
    }
}

#[derive(Clone)]
pub struct ConntrackConfirmStage {
    pub ct: Arc<Conntrack>,
}

impl Stage for ConntrackConfirmStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        ctx.ct().is_some() && ctx.ct_is_new()
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let entry = ctx.ct().unwrap().clone();

        if !self.ct.confirm(&entry) {
            tracing::debug!(
                  event = "conntrack.confirm.collision",
                  flow_id = entry.id,
                  "lost race with concurrent confirm"
              );
        }

        StageOutcome::Continue
    }
}

#[derive(Clone)]
pub struct L4StateStage {
    pub flow_stats: Arc<crate::ml::FlowStatsAggregator>,
}

impl Stage for L4StateStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool { !packet_is_decrypted(ctx) }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        populate_ml_tcp_and_flow_stats(ctx, &self.flow_stats);

        StageOutcome::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::path::PathBuf;
    use std::collections::HashMap;
    use uuid::Uuid;
    use crate::policy::Policy;

    fn sample_config() -> AppConfig {
        AppConfig {
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

    struct TestZoneInterface {
        id: &'static str,
        zone_id: &'static str,
        kind: ZoneInterfaceKind,
        sniffed: bool,
    }

    fn test_zone_interface_provider(interfaces: Vec<TestZoneInterface>) -> Arc<ZoneInterfaceProvider> {
        let mut map = HashMap::new();
        
        for iface in interfaces {
            let id = ZoneInterfaceId::from(Uuid::parse_str(iface.id).unwrap());
            let zone_interface = ZoneInterface {
                zone_id: ZoneId::from(Uuid::parse_str(iface.zone_id).unwrap()),
                kind: iface.kind,
                status: InterfaceStatus::Active,
                addresses: vec![],
                sniffed: iface.sniffed,
            };
            map.insert(id, zone_interface);
        }
        
        Arc::new(ZoneInterfaceProvider::new_for_test(map))
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
        let provider = test_zone_interface_provider(vec![TestZoneInterface {
            id: "00000000-0000-0000-0000-000000000001",
            zone_id: "00000000-0000-0000-0000-000000000002",
            kind: ZoneInterfaceKind::Physical(PhysicalInterface {
                interface_name: "eth1".to_string(),
            }),
            sniffed: true,
        }]);
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth1");
        assert!(should_halt_for_tls_redirect(&ctx, &sample_config(), &provider));
    }

    struct MockZoneResolver(ZonePairId);
    impl crate::zones::resolver::ZoneResolver for MockZoneResolver {
        fn resolve(&self, _src: &str, _dst: std::net::IpAddr) -> Option<crate::zones::ResolvedZonePair> {
            None // Return None to trigger halt in the first test
        }
    }

    // #[test]
    // fn policy_eval_stage_returns_halt_on_none_evaluator() {
    //     let engine = Arc::new(PolicyEngine::from_policies(&HashMap::new(), &HashMap::new()).unwrap());
    //     let zp_id = ZonePairId::from(Uuid::now_v7());
    //     let stage = PolicyEvalStage {
    //         policy_engine: engine,
    //         zone_resolver: Arc::new(MockZoneResolver(zp_id)),
    //         dnssec: None,
    //     };
    // 
    //     let mut ctx = tcp_context([192, 168, 1, 10], [10, 0, 0, 1], 80, "eth1");
    //     let outcome = tokio::runtime::Runtime::new()
    //         .unwrap()
    //         .block_on(stage.process(&mut ctx));
    // 
    //     assert_eq!(outcome, StageOutcome::Halt);
    // }

    #[test]
    fn policy_eval_stage_maps_allow_verdict() {
        let zp_id = ZonePairId::from(Uuid::now_v7());
        let zp = crate::zones::ZonePair {
            src_zone_id: Uuid::now_v7().into(),
            dst_zone_id: Uuid::now_v7().into(),
            default_policy: crate::zones::DefaultPolicy::Drop,
        };

        let policy = Policy {
            name: "allow-all".into(),
            zone_pair_id: zp_id.clone(),
            priority: 1,
            rule_tree: crate::rule_tree::RuleTree::new(
                crate::rule_tree::matcher::MatchBuilder::with_arm(
                    crate::rule_tree::MatchKind::IpVer,
                    crate::rule_tree::Pattern::Wildcard,
                    crate::rule_tree::ArmEnd::Verdict(Verdict::Allow),
                )
                .build()
                .unwrap(),
            ),
        };

        let mut policies = HashMap::new();
        policies.insert(crate::policy::PolicyId::from(Uuid::now_v7()), policy);

        let mut zone_pairs = HashMap::new();
        zone_pairs.insert(zp_id.clone(), zp);

        let engine = Arc::new(PolicyEngine::from_policies(&policies, &zone_pairs).unwrap());
        struct MockZoneResolverAllow(ZonePairId);
        impl crate::zones::resolver::ZoneResolver for MockZoneResolverAllow {
            fn resolve(&self, _src: &str, _dst: std::net::IpAddr) -> Option<crate::zones::ResolvedZonePair> {
                Some(crate::zones::ResolvedZonePair {
                    id: self.0.clone(),
                    default_policy: crate::zones::DefaultPolicy::Drop,
                })
            }
        }

        let stage = PolicyEvalStage {
            policy_engine: engine,
            zone_resolver: Arc::new(MockZoneResolverAllow(zp_id)),
            dnssec: None,
        };

        let mut ctx = tcp_context([192, 168, 1, 10], [10, 0, 0, 1], 80, "eth1");
        let outcome = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(stage.process(&mut ctx));

        assert_eq!(outcome, StageOutcome::Continue);
    }

    #[test]
    fn tls_redirect_ignores_unknown_interfaces() {
        let provider = test_zone_interface_provider(vec![TestZoneInterface {
            id: "00000000-0000-0000-0000-000000000001",
            zone_id: "00000000-0000-0000-0000-000000000002",
            kind: ZoneInterfaceKind::Physical(PhysicalInterface { interface_name: "eth1".to_string(),
            }),
            sniffed: true,
        }]);
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth9");
        assert!(!should_halt_for_tls_redirect(&ctx, &sample_config(), &provider));
    }

    #[test]
    fn tls_redirect_halts_on_custom_inspection_port() {
        let provider = test_zone_interface_provider(vec![TestZoneInterface {
            id: "00000000-0000-0000-0000-000000000001",
            zone_id: "00000000-0000-0000-0000-000000000002",
            kind: ZoneInterfaceKind::Physical(PhysicalInterface { interface_name: "eth1".to_string(),
            }),
            sniffed: true,
        }]);
        let mut config = sample_config();
        config.tls_inspection_ports = vec![443, 8443];
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 8443, "eth1");
        assert!(should_halt_for_tls_redirect(&ctx, &config, &provider));
    }

    #[test]
    fn tls_redirect_ignores_port_outside_inspection_list() {
        let provider = test_zone_interface_provider(vec![TestZoneInterface {
            id: "00000000-0000-0000-0000-000000000001",
            zone_id: "00000000-0000-0000-0000-000000000002",
            kind: ZoneInterfaceKind::Physical(PhysicalInterface { interface_name: "eth1".to_string(),
            }),
            sniffed: true,
        }]);
        let mut config = sample_config();
        config.tls_inspection_ports = vec![443];
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 8443, "eth1");
        assert!(!should_halt_for_tls_redirect(&ctx, &config, &provider));
    }

    #[test]
    fn should_halt_returns_true_for_sniffed_interface() {
        let provider = test_zone_interface_provider(vec![TestZoneInterface {
            id: "00000000-0000-0000-0000-000000000001",
            zone_id: "00000000-0000-0000-0000-000000000002",
            kind: ZoneInterfaceKind::Physical(PhysicalInterface { interface_name: "eth0".to_string(),
            }),
            sniffed: true,
        }]);
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth0");
        assert!(should_halt_for_tls_redirect(&ctx, &sample_config(), &provider));
    }

    #[test]
    fn should_halt_returns_false_for_unsniffed_interface() {
        let provider = test_zone_interface_provider(vec![TestZoneInterface {
            id: "00000000-0000-0000-0000-000000000001",
            zone_id: "00000000-0000-0000-0000-000000000002",
            kind: ZoneInterfaceKind::Physical(PhysicalInterface { interface_name: "eth0".to_string(),
            }),
            sniffed: false,
        }]);
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth0");
        assert!(!should_halt_for_tls_redirect(&ctx, &sample_config(), &provider));
    }

    #[test]
    fn should_halt_returns_false_for_unknown_interface() {
        let provider = test_zone_interface_provider(vec![TestZoneInterface {
            id: "00000000-0000-0000-0000-000000000001",
            zone_id: "00000000-0000-0000-0000-000000000002",
            kind: ZoneInterfaceKind::Physical(PhysicalInterface { interface_name: "eth0".to_string(),
            }),
            sniffed: true,
        }]);
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth9");
        assert!(!should_halt_for_tls_redirect(&ctx, &sample_config(), &provider));
    }

    #[test]
    fn should_halt_vlan_uses_derived_name() {
        let provider = test_zone_interface_provider(vec![
            TestZoneInterface {
                id: "00000000-0000-0000-0000-000000000001",
                zone_id: "00000000-0000-0000-0000-000000000002",
                kind: ZoneInterfaceKind::Physical(PhysicalInterface { interface_name: "eth0".to_string(),
            }),
                sniffed: false,
            },
            TestZoneInterface {
                id: "00000000-0000-0000-0000-000000000003",
                zone_id: "00000000-0000-0000-0000-000000000002",
                kind: ZoneInterfaceKind::Vlan(VlanSubinterface {
                    parent_interface_id: ZoneInterfaceId::from(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
                    vlan_id: crate::zones::VlanId::try_from(100).unwrap(),
                }),
                sniffed: true,
            },
        ]);
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth0.100");
        assert!(should_halt_for_tls_redirect(&ctx, &sample_config(), &provider));
    }

    #[test]
    fn should_halt_false_when_ssl_inspection_disabled() {
        let provider = test_zone_interface_provider(vec![TestZoneInterface {
            id: "00000000-0000-0000-0000-000000000001",
            zone_id: "00000000-0000-0000-0000-000000000002",
            kind: ZoneInterfaceKind::Physical(PhysicalInterface { interface_name: "eth0".to_string(),
            }),
            sniffed: true,
        }]);
        let mut config = sample_config();
        config.ssl_inspection_enabled = false;
        let ctx = tcp_context([10, 0, 0, 1], [192, 168, 20, 10], 443, "eth0");
        assert!(!should_halt_for_tls_redirect(&ctx, &config, &provider));
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
                attack_type: "DDoS".to_string(),
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
        assert!(ctx.borrow_warnings()[0].contains("ML threat DDoS score"));
        assert!(ctx.borrow_warnings()[0].contains("DDoS"));
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
