use std::net::IpAddr;
use std::sync::Arc;

use etherparse::NetSlice;
use tokio::sync::Mutex;

use crate::{
    data_plane::{
        dns_inspection::DnsInspection,
        nat::NatEngine,
        packet_context::PacketContext,
        tcp_session_tracker::TcpSessionTracker,
    },
    dpi::{DpiClassifier, InspectResult, TlsAction},
    packet_validator::validate, pipeline::{Stage, StageOutcome}, policy::provider::DiskPolicyProvider, rule_tree::{ArrivalInfo, Verdict},
    tls::decision_engine::TlsDecisionEngine,
};
use crate::data_plane::dns_inspection::DnsInspectionVerdict;
use crate::dpi::AppProto;

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
pub struct NatPreroutingStage {
    pub engine: Arc<Mutex<NatEngine>>,
}

impl Stage for NatPreroutingStage {
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

#[derive(Clone)]
pub struct PolicyEvalStage {
    pub provider: Arc<DiskPolicyProvider>,
}

impl Stage for PolicyEvalStage {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let arrival = ArrivalInfo::from_time(ctx.borrow_arrival_time());
        let verdict = self.provider.get_evaluator().evaluate(ctx.borrow_sliced_packet(), &arrival);

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
pub struct DnsInspectionStage {
    pub inspection: Arc<DnsInspection>,
}

impl Stage for DnsInspectionStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        match ctx.borrow_dpi_ctx() {
            Some(dpi_ctx) => {
                dpi_ctx.app_proto == Some(AppProto::Dns)
            }
            None => false,
        }
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let dpi_ctx = ctx.borrow_dpi_ctx().as_ref().unwrap();
        
        match self.inspection.process(&dpi_ctx) {
            DnsInspectionVerdict::Allow => StageOutcome::Continue,
            DnsInspectionVerdict::Alert(msg) => {
                tracing::debug!(reason = %msg, "DNS inspection alert");
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Continue
            }
            DnsInspectionVerdict::Block(msg) => {
                tracing::debug!(reason = %msg, "DNS inspection block");
                ctx.with_warnings_mut(|w| w.push(msg));
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
            InspectResult::Done(dpi_ctx) => {
                tracing::debug!("DPI: classification done ctx={dpi_ctx:?}");
                ctx.with_dpi_ctx_mut(|c| *c = Some(dpi_ctx));
            }
            InspectResult::NeedMore => {}
            InspectResult::Skipped => {}
        }
        StageOutcome::Continue
    }
}

#[derive(Clone)]
pub struct TlsInspectionStage {
    pub enabled: bool,
    pub decision_engine: Arc<TlsDecisionEngine>,
}

fn extract_dst_ip(ctx: &PacketContext) -> Option<IpAddr> {
    match &ctx.borrow_sliced_packet().net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            Some(IpAddr::V4(ipv4.header().destination_addr()))
        }
        Some(etherparse::NetSlice::Ipv6(ipv6)) => {
            Some(IpAddr::V6(ipv6.header().destination_addr()))
        }
        _ => None,
    }
}

fn extract_src_ip(ctx: &PacketContext) -> Option<IpAddr> {
    match &ctx.borrow_sliced_packet().net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            Some(IpAddr::V4(ipv4.header().source_addr()))
        }
        Some(etherparse::NetSlice::Ipv6(ipv6)) => {
            Some(IpAddr::V6(ipv6.header().source_addr()))
        }
        _ => None,
    }
}

// Wyciaga destination port z naglowka transportowego.
fn extract_dst_port(ctx: &PacketContext) -> u16 {
    match &ctx.borrow_sliced_packet().transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => tcp.destination_port(),
        Some(etherparse::TransportSlice::Udp(udp)) => udp.destination_port(),
        _ => 0,
    }
}

impl Stage for TlsInspectionStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        self.enabled && matches!(
            ctx.borrow_dpi_ctx(),
            Some(dpi_ctx) if dpi_ctx.app_proto == Some(AppProto::Tls)
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let (sni, ech_detected) = match ctx.borrow_dpi_ctx() {
            Some(dpi_ctx) => (dpi_ctx.tls_sni.clone(), dpi_ctx.tls_ech_detected),
            None => return StageOutcome::Continue,
        };

        let dst_ip = extract_dst_ip(ctx);
        let dst_port = extract_dst_port(ctx);
        let src_ip = extract_src_ip(ctx);

        let action = self.decision_engine.decide(sni.as_deref(), ech_detected, dst_ip, dst_port, src_ip);

        tracing::debug!(
            sni = sni.as_deref().unwrap_or("none"),
            ech = ech_detected,
            ?dst_ip,
            dst_port,
            action = ?action,
            "TLS inspection decision"
        );

        ctx.with_dpi_ctx_mut(|c| {
            if let Some(dpi) = c.as_mut() {
                dpi.tls_action = action;
            }
        });

        match action {
            TlsAction::Block => StageOutcome::Halt,
            _ => StageOutcome::Continue,
        }
    }
}
