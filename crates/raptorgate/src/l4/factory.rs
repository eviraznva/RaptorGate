use std::marker::PhantomData;
use std::sync::Arc;

use crate::conntrack::entry::ConntrackEntry;
use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::smtp::smtp_policy_retriever::SmtpPolicyRetriever;
use crate::dpi::stages::{SmtpL4Stage, SshL4Stage};
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::http::HttpL4Stage;
use crate::l4::noop::{NoopIcmpStage, NoopUdpStage};
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage, TerminateReason};
use crate::l4::tls::TlsHttpL4Stage;
use crate::tls::l4_inspection::{TlsL4InspectionConfig, TlsL4InspectionService};
use crate::zones::resolver::ZoneResolver;

pub type UdpNoopPipeline = NoopUdpStage;
pub type IcmpNoopPipeline = NoopIcmpStage;

pub enum TcpSessionPipeline<ZR: ZoneResolver> {
    Http(HttpL4Stage),
    Smtp(SmtpL4Stage<ZR>),
    Ssh(SshL4Stage<ZR>),
    TlsHttp(TlsHttpL4Stage),
    #[cfg(test)]
    TestOutcome(TcpTestOutcomeStage),
    PassThrough(TcpPassThroughStage),
    ForceTerminate(TcpForceTerminateStage),
}

impl<ZR: ZoneResolver> TcpSessionPipeline<ZR> {
    pub fn protocol(&self) -> AppProto {
        match self {
            Self::Http(s) => s.protocol(),
            Self::Smtp(s) => s.protocol(),
            Self::Ssh(s) => s.protocol(),
            Self::TlsHttp(s) => s.protocol(),
            #[cfg(test)]
            Self::TestOutcome(s) => s.protocol(),
            Self::PassThrough(s) => s.protocol(),
            Self::ForceTerminate(s) => s.protocol(),
        }
    }

    pub async fn on_session_open(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        match self {
            Self::Http(s) => s.on_session_open(ctx).await,
            Self::Smtp(s) => s.on_session_open(ctx).await,
            Self::Ssh(s) => s.on_session_open(ctx).await,
            Self::TlsHttp(s) => s.on_session_open(ctx).await,
            #[cfg(test)]
            Self::TestOutcome(s) => s.on_session_open(ctx).await,
            Self::PassThrough(s) => s.on_session_open(ctx).await,
            Self::ForceTerminate(s) => s.on_session_open(ctx).await,
        }
    }

    pub async fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        match self {
            Self::Http(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload).await,
            Self::Smtp(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload).await,
            Self::Ssh(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload).await,
            Self::TlsHttp(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload).await,
            #[cfg(test)]
            Self::TestOutcome(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload).await,
            Self::PassThrough(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload).await,
            Self::ForceTerminate(s) => s.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload).await,
        }
    }

    pub async fn drain(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        match self {
            Self::Http(s) => s.drain(ctx).await,
            Self::Smtp(s) => s.drain(ctx).await,
            Self::Ssh(s) => s.drain(ctx).await,
            Self::TlsHttp(s) => s.drain(ctx).await,
            #[cfg(test)]
            Self::TestOutcome(s) => s.drain(ctx).await,
            Self::PassThrough(s) => s.drain(ctx).await,
            Self::ForceTerminate(s) => s.drain(ctx).await,
        }
    }

    pub async fn on_session_close(&mut self, ctx: &mut SessionContext, reason: CloseReason) {
        match self {
            Self::Http(s) => s.on_session_close(ctx, reason).await,
            Self::Smtp(s) => s.on_session_close(ctx, reason).await,
            Self::Ssh(s) => s.on_session_close(ctx, reason).await,
            Self::TlsHttp(s) => s.on_session_close(ctx, reason).await,
            #[cfg(test)]
            Self::TestOutcome(s) => s.on_session_close(ctx, reason).await,
            Self::PassThrough(s) => s.on_session_close(ctx, reason).await,
            Self::ForceTerminate(s) => s.on_session_close(ctx, reason).await,
        }
    }
}

#[derive(Debug, Default)]
pub struct TcpPassThroughStage;

#[tonic::async_trait]
impl L4Stage for TcpPassThroughStage {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Unknown
    }

    async fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
        L4Outcome::Continue
    }

    async fn on_bytes(
        &mut self,
        _ctx: &mut SessionContext,
        packet_id: PacketId,
        _dir: Direction,
        _tcp_payload_start_seq: u32,
        _payload: &[u8],
    ) -> L4Outcome {
        L4Outcome::Forward(vec![packet_id])
    }

    async fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {}
}

#[derive(Debug, Default)]
pub struct TcpForceTerminateStage;

#[tonic::async_trait]
impl L4Stage for TcpForceTerminateStage {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Smtp
    }

    async fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
        L4Outcome::Continue
    }

    async fn on_bytes(
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

    async fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {}
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub enum TcpTestOutcome {
    DropCurrent,
    Emit { dir: Direction, payload: Vec<u8> },
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TcpTestOutcomeStage {
    outcome: TcpTestOutcome,
}

#[cfg(test)]
impl TcpTestOutcomeStage {
    fn new(outcome: TcpTestOutcome) -> Self {
        Self { outcome }
    }
}

#[cfg(test)]
#[tonic::async_trait]
impl L4Stage for TcpTestOutcomeStage {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Unknown
    }

    async fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
        L4Outcome::Continue
    }

    async fn on_bytes(
        &mut self,
        _ctx: &mut SessionContext,
        packet_id: PacketId,
        _dir: Direction,
        _tcp_payload_start_seq: u32,
        _payload: &[u8],
    ) -> L4Outcome {
        match &self.outcome {
            TcpTestOutcome::DropCurrent => L4Outcome::Drop(vec![packet_id]),
            TcpTestOutcome::Emit { dir, payload } => L4Outcome::ForwardAndEmit {
                forward: Vec::new(),
                emit: vec![crate::l4::stage::L4Emit {
                    dir: *dir,
                    payload: payload.clone(),
                }],
            },
        }
    }

    async fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {}
}

#[derive(Clone)]
enum TcpFactoryKind<ZR: ZoneResolver> {
    ApplicationRouter {
        smtp_policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
        tls_inspection: Option<Arc<TlsL4InspectionConfig>>,
    },
    Http,
    ForceTerminate,
    #[cfg(test)]
    TestOutcome(TcpTestOutcome),
}

#[derive(Clone)]
pub struct TcpL4PipelineFactory<ZR: ZoneResolver> {
    kind: TcpFactoryKind<ZR>,
    _zr: PhantomData<ZR>,
}

impl<ZR: ZoneResolver> TcpL4PipelineFactory<ZR> {
    pub fn new_application_router(
        policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
        tls_inspection: Option<Arc<TlsL4InspectionConfig>>,
    ) -> Self {
        Self {
            kind: TcpFactoryKind::ApplicationRouter {
                smtp_policy_retriever: policy_retriever,
                tls_inspection,
            },
            _zr: PhantomData,
        }
    }

    pub fn new_http() -> Self {
        Self {
            kind: TcpFactoryKind::Http,
            _zr: PhantomData,
        }
    }

    pub fn new_force_terminate() -> Self {
        Self {
            kind: TcpFactoryKind::ForceTerminate,
            _zr: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_test_drop_current() -> Self {
        Self {
            kind: TcpFactoryKind::TestOutcome(TcpTestOutcome::DropCurrent),
            _zr: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_test_emit(dir: Direction, payload: Vec<u8>) -> Self {
        Self {
            kind: TcpFactoryKind::TestOutcome(TcpTestOutcome::Emit { dir, payload }),
            _zr: PhantomData,
        }
    }

    pub fn build(&self) -> TcpSessionPipeline<ZR> {
        match &self.kind {
            TcpFactoryKind::ApplicationRouter { .. } => TcpSessionPipeline::PassThrough(TcpPassThroughStage::default()),
            TcpFactoryKind::Http => TcpSessionPipeline::Http(HttpL4Stage::new()),
            TcpFactoryKind::ForceTerminate => TcpSessionPipeline::ForceTerminate(TcpForceTerminateStage::default()),
            #[cfg(test)]
            TcpFactoryKind::TestOutcome(outcome) => TcpSessionPipeline::TestOutcome(TcpTestOutcomeStage::new(outcome.clone())),
        }
    }

    pub fn build_for_entry(&self, entry: &ConntrackEntry) -> TcpSessionPipeline<ZR> {
        match &self.kind {
            TcpFactoryKind::ApplicationRouter {
                smtp_policy_retriever,
                tls_inspection,
            } => {
                let src = entry.original.src_port;
                let dst = entry.original.dst_port;
                if src == 465 || dst == 465 {
                    TcpSessionPipeline::PassThrough(TcpPassThroughStage::default())
                } else if matches!(src, 25 | 587) || matches!(dst, 25 | 587) {
                    TcpSessionPipeline::Smtp(SmtpL4Stage::new(Arc::clone(smtp_policy_retriever)))
                } else if src == 22 || dst == 22 {
                    TcpSessionPipeline::Ssh(SshL4Stage::new(Arc::clone(smtp_policy_retriever)))
                } else if src == 80 || dst == 80 {
                    TcpSessionPipeline::Http(HttpL4Stage::new())
                } else if (src == 443 || dst == 443) && tls_inspection.is_some() {
                    let tls_inspection = tls_inspection.as_ref().expect("checked is_some");
                    TcpSessionPipeline::TlsHttp(TlsHttpL4Stage::new(TlsL4InspectionService::new(Arc::clone(tls_inspection))))
                } else {
                    TcpSessionPipeline::PassThrough(TcpPassThroughStage::default())
                }
            }
            _ => self.build(),
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
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::policy::provider::DiskPolicyProvider;
    use crate::conntrack::proto::tcp::TcpProtoState;
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

    fn sample_tcp_entry() -> Arc<ConntrackEntry> {
        sample_tcp_entry_with_ports(12345, 80)
    }

    fn sample_tcp_entry_with_ports(src_port: u16, dst_port: u16) -> Arc<ConntrackEntry> {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port,
            Protocol::Tcp,
        );
        Arc::new(ConntrackEntry::new(
            2,
            tuple,
            ProtoState::Tcp(TcpProtoState::default()),
            Duration::from_secs(60),
            0,
        ))
    }

    fn smtp_policy_retriever() -> Arc<SmtpPolicyRetriever<StubZoneResolver>> {
        Arc::new(SmtpPolicyRetriever::new(
            Arc::new(StubZoneResolver),
            Arc::new(DiskPolicyProvider::from_policies(HashMap::new(), PathBuf::from("/tmp"))),
        ))
    }

    fn tls_inspection_config() -> Arc<TlsL4InspectionConfig> {
        Arc::new(TlsL4InspectionConfig::test_with_bypass_domains(&[]))
    }

    #[tokio::test]
    async fn udp_factory_pipeline_forwards_packet_id() {
        let mut pipe = UdpL4PipelineFactory::default().build();
        let mut ctx = SessionContext::open(sample_udp_entry(), &StubZoneResolver);
        let id = PacketId::next();
        let o = pipe.on_bytes(&mut ctx, id, Direction::Original, 0, b"x").await;
        assert_eq!(o, L4Outcome::Forward(vec![id]));
    }

    #[tokio::test]
    async fn icmp_factory_pipeline_forwards_packet_id() {
        let mut pipe = IcmpL4PipelineFactory::default().build();
        let mut ctx = SessionContext::open(sample_udp_entry(), &StubZoneResolver);
        let id = PacketId::next();
        let o = pipe.on_bytes(&mut ctx, id, Direction::Original, 0, b"x").await;
        assert_eq!(o, L4Outcome::Forward(vec![id]));
    }

    #[tokio::test]
    async fn http_factory_pipeline_tracks_http_request_state() {
        let mut pipe = TcpL4PipelineFactory::<StubZoneResolver>::new_http().build();
        let mut ctx = SessionContext::open(sample_tcp_entry(), &StubZoneResolver);

        assert_eq!(pipe.on_session_open(&mut ctx).await, L4Outcome::Continue);

        let id = PacketId::next();
        let out = pipe.on_bytes(
            &mut ctx,
            id,
            Direction::Original,
            0,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n",
        ).await;

        assert_eq!(out, L4Outcome::Forward(vec![id]));
        assert_eq!(ctx.application_protocol(), Some(AppProto::Http));

        let TcpSessionPipeline::Http(stage) = pipe else {
            panic!("expected HTTP pipeline");
        };
        let dpi = stage.dpi_context();
        assert_eq!(dpi.app_proto, Some(AppProto::Http));
        assert_eq!(dpi.http_method.as_deref(), Some("GET"));
        assert_eq!(dpi.http_host.as_deref(), Some("example.com"));
        assert_eq!(dpi.http_user_agent.as_deref(), Some("test"));
    }

    #[tokio::test]
    async fn application_router_selects_http_smtp_ssh_or_passthrough_by_port() {
        let factory = TcpL4PipelineFactory::new_application_router(smtp_policy_retriever(), Some(tls_inspection_config()));

        assert!(matches!(
            factory.build_for_entry(&sample_tcp_entry_with_ports(12345, 80)),
            TcpSessionPipeline::Http(_)
        ));
        assert!(matches!(
            factory.build_for_entry(&sample_tcp_entry_with_ports(12345, 25)),
            TcpSessionPipeline::Smtp(_)
        ));
        assert!(matches!(
            factory.build_for_entry(&sample_tcp_entry_with_ports(12345, 22)),
            TcpSessionPipeline::Ssh(_)
        ));
    }

    #[tokio::test]
    async fn ssh_factory_pipeline_forwards_packet_id() {
        let factory = TcpL4PipelineFactory::<StubZoneResolver>::new_application_router(
            smtp_policy_retriever(),
            Some(tls_inspection_config()),
        );
        let mut pipe = factory.build_for_entry(&sample_tcp_entry_with_ports(12345, 22));
        let mut ctx = SessionContext::open(sample_tcp_entry_with_ports(12345, 22), &StubZoneResolver);

        let id = PacketId::next();
        let out = pipe.on_bytes(&mut ctx, id, Direction::Original, 0, b"SSH-2.0-OpenSSH_8.9\r\n").await;

        assert_eq!(out, L4Outcome::Forward(vec![id]));

        let TcpSessionPipeline::Ssh(stage) = pipe else {
            panic!("expected SSH pipeline");
        };
        assert_eq!(stage.protocol(), AppProto::Ssh);
    }

    #[tokio::test]
    async fn application_router_selects_tls_http_for_https() {
        let factory = TcpL4PipelineFactory::new_application_router(smtp_policy_retriever(), Some(tls_inspection_config()));

        assert!(matches!(
            factory.build_for_entry(&sample_tcp_entry_with_ports(12345, 443)),
            TcpSessionPipeline::TlsHttp(_)
        ));
    }

    #[tokio::test]
    async fn application_router_bypasses_smtps_for_now() {
        let factory = TcpL4PipelineFactory::new_application_router(smtp_policy_retriever(), Some(tls_inspection_config()));

        assert!(matches!(
            factory.build_for_entry(&sample_tcp_entry_with_ports(12345, 465)),
            TcpSessionPipeline::PassThrough(_)
        ));
    }
}
