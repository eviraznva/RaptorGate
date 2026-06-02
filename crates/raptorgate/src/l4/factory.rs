use std::marker::PhantomData;
use std::sync::Arc;

use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::smtp_l4_stage::SmtpL4Stage;
use crate::dpi::smtp_policy_retriever::SmtpPolicyRetriever;
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::noop::{NoopIcmpStage, NoopUdpStage};
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage, TerminateReason};
use crate::zones::resolver::ZoneResolver;

pub type UdpNoopPipeline = NoopUdpStage;
pub type IcmpNoopPipeline = NoopIcmpStage;

pub enum TcpSessionPipeline<ZR: ZoneResolver> {
    Smtp(SmtpL4Stage<ZR>),
    ForceTerminate(TcpForceTerminateStage),
}

impl<ZR: ZoneResolver> TcpSessionPipeline<ZR> {
    pub fn protocol(&self) -> AppProto {
        match self {
            Self::Smtp(s) => s.protocol(),
            Self::ForceTerminate(s) => s.protocol(),
        }
    }

    pub fn on_session_open(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        match self {
            Self::Smtp(s) => s.on_session_open(ctx),
            Self::ForceTerminate(s) => s.on_session_open(ctx),
        }
    }

    pub fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        match self {
            Self::Smtp(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload),
            Self::ForceTerminate(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload),
        }
    }

    pub fn on_session_close(&mut self, ctx: &mut SessionContext, reason: CloseReason) {
        match self {
            Self::Smtp(s) => s.on_session_close(ctx, reason),
            Self::ForceTerminate(s) => s.on_session_close(ctx, reason),
        }
    }
}

#[derive(Debug, Default)]
pub struct TcpForceTerminateStage;

impl L4Stage for TcpForceTerminateStage {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Smtp
    }

    fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
        L4Outcome::Continue
    }

    fn on_bytes(
        &mut self,
        _ctx: &mut SessionContext,
        _packet_id: PacketId,
        _dir: Direction,
        _tcp_payload_start_seq: u32,
        _payload: &[u8],
    ) -> L4Outcome {
        L4Outcome::Terminate {
            reason: TerminateReason::SmtpPolicyDenied,
            reset: true,
        }
    }

    fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {}
}

#[derive(Clone)]
enum TcpFactoryKind<ZR: ZoneResolver> {
    Smtp(Arc<SmtpPolicyRetriever<ZR>>),
    ForceTerminate,
}

#[derive(Clone)]
pub struct TcpL4PipelineFactory<ZR: ZoneResolver> {
    kind: TcpFactoryKind<ZR>,
    _zr: PhantomData<ZR>,
}

impl<ZR: ZoneResolver> TcpL4PipelineFactory<ZR> {
    pub fn new_smtp(policy_retriever: Arc<SmtpPolicyRetriever<ZR>>) -> Self {
        Self {
            kind: TcpFactoryKind::Smtp(policy_retriever),
            _zr: PhantomData,
        }
    }

    pub fn new_force_terminate() -> Self {
        Self {
            kind: TcpFactoryKind::ForceTerminate,
            _zr: PhantomData,
        }
    }

    pub fn build(&self) -> TcpSessionPipeline<ZR> {
        match &self.kind {
            TcpFactoryKind::Smtp(p) => TcpSessionPipeline::Smtp(SmtpL4Stage::new(Arc::clone(p))),
            TcpFactoryKind::ForceTerminate => TcpSessionPipeline::ForceTerminate(TcpForceTerminateStage::default()),
        }
    }
}

impl<ZR: ZoneResolver> Default for TcpL4PipelineFactory<ZR> {
    fn default() -> Self {
        Self::new_force_terminate()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UdpL4PipelineFactory;

impl UdpL4PipelineFactory {
    pub fn build(&self) -> UdpNoopPipeline {
        NoopUdpStage::default()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct IcmpL4PipelineFactory;

impl IcmpL4PipelineFactory {
    pub fn build(&self) -> IcmpNoopPipeline {
        NoopIcmpStage::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use crate::conntrack::proto::udp::UdpProtoState;
    use crate::conntrack::proto::ProtoState;
    use crate::conntrack::tuple::{FlowTuple, Protocol};
    use crate::conntrack::entry::ConntrackEntry;
    use crate::zones::resolver::ZoneResolver;
    use crate::zones::{DirectionalZonePairs, ResolvedZonePair, ZonePairId};

    #[derive(Clone)]
    struct StubZoneResolver;

    impl ZoneResolver for StubZoneResolver {
        fn resolve(&self, _src_interface_name: &str, _dst_ip: IpAddr) -> Option<ResolvedZonePair> {
            Some(ResolvedZonePair {
                id: ZonePairId::from(uuid::Uuid::nil()),
                default_policy: crate::zones::DefaultPolicy::Allow,
            })
        }

        fn resolve_bidirectional(&self, _src_ip: IpAddr, _dst_ip: IpAddr) -> DirectionalZonePairs {
            let pair = ResolvedZonePair {
                id: ZonePairId::from(uuid::Uuid::nil()),
                default_policy: crate::zones::DefaultPolicy::Allow,
            };
            DirectionalZonePairs {
                forward: Some(pair.clone()),
                reverse: Some(pair),
            }
        }
    }

    fn sample_udp_entry() -> Arc<ConntrackEntry> {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            2000,
            Protocol::Udp,
        );
        Arc::new(ConntrackEntry::new(
            1,
            tuple,
            ProtoState::Udp(UdpProtoState::default()),
            Duration::from_secs(60),
            0,
        ))
    }

    #[test]
    fn udp_factory_pipeline_forwards_packet_id() {
        let mut pipe = UdpL4PipelineFactory::default().build();
        let mut ctx = SessionContext::open(sample_udp_entry(), &StubZoneResolver);
        let id = PacketId::next();
        let o = pipe.on_bytes(&mut ctx, id, Direction::Original, 0, b"x");
        assert_eq!(o, L4Outcome::Forward(vec![id]));
    }

    #[test]
    fn icmp_factory_pipeline_forwards_packet_id() {
        let mut pipe = IcmpL4PipelineFactory::default().build();
        let mut ctx = SessionContext::open(sample_udp_entry(), &StubZoneResolver);
        let id = PacketId::next();
        let o = pipe.on_bytes(&mut ctx, id, Direction::Original, 0, b"x");
        assert_eq!(o, L4Outcome::Forward(vec![id]));
    }
}
