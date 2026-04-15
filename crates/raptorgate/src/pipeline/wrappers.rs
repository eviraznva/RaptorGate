use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use etherparse::{NetSlice, TransportSlice};
use tokio::sync::Mutex;

use crate::{
    config::AppConfig,
    config_provider::AppConfigProvider,
    data_plane::{
        dns_inspection::dns_inspection::{BlocklistVerdict, DnsInspection, EchMitigationVerdict},
        ips::ips::{Ips, IpsVerdict},
        nat::NatEngine,
        packet_context::PacketContext,
        tcp_session_tracker::TcpSessionTracker,
    },
    dpi::{DpiClassifier, InspectResult},
    packet_validator::validate,
    pipeline::{Stage, StageOutcome},
    policy::provider::DiskPolicyProvider,
    rule_tree::{ArrivalInfo, Verdict},
};

use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::data_plane::dns_inspection::tunneling_detector::DnsInspectionVerdict;
use crate::dpi::AppProto;
use crate::policy::policy_evaluator::DnsEvalContext;

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
                tracing::debug!(reason = %e, "packet failed validation");
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
        Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == 443
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
pub struct NatPostroutingStage {
    pub engine: Arc<Mutex<NatEngine>>,
}

impl Stage for NatPostroutingStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        !packet_is_decrypted(ctx)
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let dst_ip = match &ctx.borrow_sliced_packet().net {
            Some(NetSlice::Ipv4(ipv4)) => IpAddr::V4(ipv4.header().destination_addr()),
            Some(NetSlice::Ipv6(ipv6)) => IpAddr::V6(ipv6.header().destination_addr()),
            _ => return StageOutcome::Continue,
        };

        let Some(out_iface) = infer_out_interface(dst_ip) else {
            return StageOutcome::Continue;
        };

        let mut engine = self.engine.lock().await;

        // Safety: same invariant as NatPreroutingStage.
        let raw_mut = unsafe {
            let ptr = ctx.borrow_raw().as_ptr() as *mut u8;
            std::slice::from_raw_parts_mut(ptr, ctx.borrow_raw().len())
        };

        engine.process_postrouting(raw_mut, out_iface, None);
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
                Err(_) => return StageOutcome::Halt,
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

// FIXME: no ale nie hardcodujemy tego pany, to czeba sie kernela pytac
// Kiedyś się zaimplementuje
fn infer_out_interface(dst_ip: IpAddr) -> Option<&'static str> {
    match dst_ip {
        IpAddr::V4(ip) if ip.octets()[0..3] == [192, 168, 10] => Some("eth1"),
        IpAddr::V4(ip) if ip.octets()[0..3] == [192, 168, 20] => Some("eth2"),
        IpAddr::V6(ip) if ip.segments()[0] == 0xfd10 => Some("eth1"),
        IpAddr::V6(ip) if ip.segments()[0] == 0xfd20 => Some("eth2"),
        _ => None,
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
                tracing::debug!(reason = %msg, "DNS blocklist block");
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
                tracing::debug!(reason = %msg, "DNS tunneling alert");
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Continue
            }
            DnsInspectionVerdict::Block(msg) => {
                tracing::debug!(reason = %msg, "DNS tunneling block");
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
            IpsVerdict::Alert(msg) => {
                tracing::debug!(reason = %msg, "IPS alert");
                ctx.with_dpi_ctx_mut(|dpi| {
                    if let Some(dpi) = dpi.as_mut() {
                        dpi.ips_match = Some(crate::dpi::IpsMatch {
                            signature_name: msg.clone(),
                            severity: "medium".to_string(),
                            blocked: false,
                        });
                    }
                });
                ctx.with_warnings_mut(|warnings| warnings.push(msg));
                StageOutcome::Continue
            }
            IpsVerdict::Block(msg) => {
                tracing::debug!(reason = %msg, "IPS block");
                ctx.with_dpi_ctx_mut(|dpi| {
                    if let Some(dpi) = dpi.as_mut() {
                        dpi.ips_match = Some(crate::dpi::IpsMatch {
                            signature_name: msg.clone(),
                            severity: "high".to_string(),
                            blocked: true,
                        });
                    }
                });
                ctx.with_warnings_mut(|warnings| warnings.push(msg));
                StageOutcome::Halt
            }
        }
    }
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

        let verdict = self.provider.get_evaluator().evaluate(
            ctx.borrow_sliced_packet(),
            &arrival,
            dns_ctx.as_ref(),
        );

        match verdict {
            Verdict::Allow => StageOutcome::Continue,
            Verdict::Drop => StageOutcome::Halt,
            Verdict::AllowWarn(msg) => {
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Continue
            }
            Verdict::DropWarn(msg) => {
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Halt
            }
        }
    }
}

#[derive(Clone)]
pub struct TcpClassificationStage {
    pub tracker: Arc<TcpSessionTracker>,
}

impl Stage for TcpClassificationStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        !packet_is_decrypted(ctx)
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        match self.tracker.process_packet(ctx.borrow_sliced_packet()) {
            Ok(_) => StageOutcome::Continue,
            Err(e) => {
                tracing::error!(error = %e, "TCP session tracking error");
                StageOutcome::Halt
            }
        }
    }
}

#[derive(Clone)]
pub struct DpiStage {
    pub classifier: Arc<DpiClassifier>,
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
                tracing::debug!("DPI: classification done ctx={dpi_ctx:?}");
                ctx.with_dpi_ctx_mut(|c| *c = Some(dpi_ctx));
            }
            InspectResult::NeedMore => {}
            InspectResult::Skipped => {}
        }
        StageOutcome::Continue
    }
}

fn merge_preserved_dpi_fields(existing: Option<&crate::dpi::DpiContext>, next: &mut crate::dpi::DpiContext) {
    let Some(existing) = existing else {
        return;
    };

    next.decrypted |= existing.decrypted;
    next.src_port = next.src_port.or(existing.src_port);
    next.dst_port = next.dst_port.or(existing.dst_port);
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
            grpc_socket_path: "/tmp/firewall.sock".into(),
            query_socket_path: "/tmp/query.sock".into(),
            dev_config: None,
            pki_dir: "/tmp/pki".into(),
            ssl_inspection_enabled: true,
            mitm_listen_addr: "127.0.0.1:8443".into(),
            control_plane_socket_path: "/tmp/control.sock".into(),
            ssl_bypass_domains: Vec::new(),
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
}
