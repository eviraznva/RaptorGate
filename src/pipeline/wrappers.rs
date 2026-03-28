use std::net::IpAddr;
use std::sync::Arc;

use etherparse::NetSlice;
use tokio::sync::Mutex;

use crate::{
    data_plane::{
        dns_inspection::DnsInspection,
        nat::engine::NatEngine,
        packet_context::PacketContext,
        policy_store::PolicyStore,
        tcp_session_tracker::TcpSessionTracker,
    },
    packet_validator::validate,
    pipeline::{Stage, StageOutcome},
    rule_tree::{ArrivalInfo, Verdict},
};

#[derive(Clone)]
pub struct ValidationStage;

impl Stage for ValidationStage {
    fn is_applicable(&self, ctx: &PacketContext) -> bool {
        matches!(&ctx.borrow_sliced_packet().net, Some(NetSlice::Ipv4(_)))
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

// FIXME: no ale nie hardcodujemy tego pany, to czeba sie kernela pytac
// Kiedyś się zaimplementuje
fn infer_out_interface(dst_ip: IpAddr) -> Option<&'static str> {
    match dst_ip {
        IpAddr::V4(ip) if ip.octets()[0..3] == [192, 168, 10] => Some("eth1"),
        IpAddr::V4(ip) if ip.octets()[0..3] == [192, 168, 20] => Some("eth2"),
        _ => None,
    }
}

#[derive(Clone)]
pub struct PolicyEvalStage {
    pub policies: Arc<PolicyStore>,
}

impl Stage for PolicyEvalStage {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let compiled = self.policies.load();
        let arrival = ArrivalInfo::from_time(ctx.borrow_arrival_time());
        let verdict = compiled.evaluator().evaluate(ctx.borrow_sliced_packet(), &arrival);

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
        use etherparse::TransportSlice;
        
        matches!(
            &ctx.borrow_sliced_packet().transport,
            Some(TransportSlice::Udp(udp)) if udp.destination_port() == 53
        )
    }

    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        use etherparse::TransportSlice;

        let payload = match &ctx.borrow_sliced_packet().transport {
            Some(TransportSlice::Udp(udp)) => udp.payload().to_vec(),
            _ => return StageOutcome::Continue,
        };

        if self.inspection.process(&payload) {
            tracing::debug!("DNS query blocked by domain blocklist");
            StageOutcome::Halt
        } else {
            StageOutcome::Continue
        }
    }
}
