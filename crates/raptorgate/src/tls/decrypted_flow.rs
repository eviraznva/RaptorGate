use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use tonic::async_trait;

use crate::data_plane::dns_inspection::dnssec::DnssecProvider;
use crate::data_plane::ips::ips::{Ips, IpsSignatureMatch, IpsVerdict};
use crate::dpi::{AppProto, DpiClassifier, DpiContext, InspectResult, IpsMatch};
use crate::events;
use crate::identity::IdentityContext;
use crate::policy::engine::PolicyEngine;
use crate::policy::policy_evaluator::{DnsEvalContext, PolicyEvalContext, PolicyFlowFields};
use crate::rule_tree::{ArrivalInfo, IpVer, Port, Protocol, Verdict};
use crate::tls::session_meta::{Direction, SessionMeta};
use crate::zones::resolver::ZoneResolver;

pub struct DecryptedFlowContext {
    pub payload: Vec<u8>,
    pub dpi: DpiContext,
    pub direction: Direction,
    pub session: SessionMeta,
    pub arrival_time: SystemTime,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub source_interface: Option<String>,
    pub identity: Option<IdentityContext>,
    pub warnings: Vec<String>,
}

impl DecryptedFlowContext {
    pub fn new(
        payload: Vec<u8>,
        mut dpi: DpiContext,
        direction: Direction,
        session: SessionMeta,
        arrival_time: SystemTime,
        identity: Option<IdentityContext>,
    ) -> Self {
        let (src, dst) = endpoints_for_direction(&session, direction);
        dpi.decrypted = true;
        dpi.src_port = Some(src.port());
        dpi.dst_port = Some(dst.port());

        Self {
            payload,
            dpi,
            direction,
            source_interface: session.source_interface_for_direction(direction).map(str::to_string),
            session,
            arrival_time,
            src,
            dst,
            identity,
            warnings: Vec::new(),
        }
    }

    fn policy_flow(&self) -> PolicyFlowFields {
        PolicyFlowFields {
            src_ip: self.src.ip(),
            dst_ip: self.dst.ip(),
            ip_ver: ip_version_for(self.src.ip()),
            protocol: Protocol::Tcp,
            src_port: Some(Port::from(self.src.port())),
            dst_port: Some(Port::from(self.dst.port())),
        }
    }
}

pub enum DecryptedFlowOutcome {
    Continue,
    Drop,
}

#[async_trait]
pub trait DecryptedFlowStage: Send + Sync {
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome;
}

pub struct DecryptedFlowPipeline {
    stages: Vec<Arc<dyn DecryptedFlowStage>>,
}

impl DecryptedFlowPipeline {
    pub fn new(stages: Vec<Arc<dyn DecryptedFlowStage>>) -> Self {
        Self { stages }
    }

    pub async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome {
        for stage in &self.stages {
            if matches!(stage.process(ctx).await, DecryptedFlowOutcome::Drop) {
                return DecryptedFlowOutcome::Drop;
            }
        }
        DecryptedFlowOutcome::Continue
    }
}

pub struct DecryptedDpiStage {
    classifier: Arc<DpiClassifier>,
}

impl DecryptedDpiStage {
    pub fn new(classifier: Arc<DpiClassifier>) -> Self {
        Self { classifier }
    }
}

#[async_trait]
impl DecryptedFlowStage for DecryptedDpiStage {
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome {
        match self.classifier.inspect_flow_payload(
            ctx.src.ip(),
            ctx.src.port(),
            ctx.dst.ip(),
            ctx.dst.port(),
            &ctx.payload,
        ) {
            InspectResult::Done(next) => merge_dpi_context(&mut ctx.dpi, next, ctx.src.port(), ctx.dst.port()),
            InspectResult::NeedMore | InspectResult::Skipped => {}
        }
        DecryptedFlowOutcome::Continue
    }
}

pub struct DecryptedIpsStage {
    ips: Arc<Ips>,
}

impl DecryptedIpsStage {
    pub fn new(ips: Arc<Ips>) -> Self {
        Self { ips }
    }
}

#[async_trait]
impl DecryptedFlowStage for DecryptedIpsStage {
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome {
        ctx.dpi.ips_match = None;
        let inspected = ctx
            .dpi
            .http_normalized_payload
            .as_deref()
            .unwrap_or(&ctx.payload);

        match self.ips.inspect_decrypted(
            inspected,
            ctx.dpi.app_proto,
            ctx.src.port(),
            ctx.dst.port(),
        ) {
            IpsVerdict::Allow => DecryptedFlowOutcome::Continue,
            IpsVerdict::Alert(matches) => {
                if let Some(first) = matches.first() {
                    ctx.dpi.ips_match = Some(match_to_dpi(first, false));
                }
                if !matches.is_empty() {
                    ctx.warnings.push(matches.iter().map(IpsSignatureMatch::message).collect::<Vec<_>>().join("; "));
                }
                DecryptedFlowOutcome::Continue
            }
            IpsVerdict::Block(matched) => {
                ctx.dpi.ips_match = Some(match_to_dpi(&matched, true));
                ctx.warnings.push(matched.message());
                DecryptedFlowOutcome::Drop
            }
        }
    }
}

pub struct DecryptedPolicyStage {
    policy_engine: Arc<PolicyEngine>,
    zone_resolver: Arc<dyn ZoneResolver>,
    dnssec: Option<Arc<dyn DnssecProvider>>,
}

impl DecryptedPolicyStage {
    pub fn new(
        policy_engine: Arc<PolicyEngine>,
        zone_resolver: Arc<dyn ZoneResolver>,
        dnssec: Option<Arc<dyn DnssecProvider>>,
    ) -> Self {
        Self { policy_engine, zone_resolver, dnssec }
    }
}

#[async_trait]
impl DecryptedFlowStage for DecryptedPolicyStage {
    async fn process(&self, ctx: &mut DecryptedFlowContext) -> DecryptedFlowOutcome {
        let Some(source_interface) = ctx.source_interface.as_deref() else {
            tracing::warn!(
                peer = %ctx.session.peer,
                server = %ctx.session.server,
                direction = ?ctx.direction,
                "decrypted policy evaluation skipped because source interface is unknown"
            );
            return DecryptedFlowOutcome::Continue;
        };

        let flow = ctx.policy_flow();
        let Some(pair) = self.zone_resolver.resolve(source_interface, flow.dst_ip) else {
            tracing::warn!(
                event = "policy.zone_pair.missing",
                iface = %source_interface,
                dst_ip = %flow.dst_ip,
                "no matching zone pair for decrypted flow, allowing"
            );
            return DecryptedFlowOutcome::Continue;
        };

        let arrival = ArrivalInfo::from_time(&ctx.arrival_time);
        let dns_ctx = dns_eval_context(self.dnssec.as_ref(), &ctx.dpi).await;
        let verdict = self.policy_engine.evaluate(&pair.id, PolicyEvalContext {
            flow,
            arrival: &arrival,
            dns: dns_ctx.as_ref(),
            dpi: Some(&ctx.dpi),
            identity: ctx.identity.as_ref(),
        });

        match verdict {
            Some(Verdict::Allow) => DecryptedFlowOutcome::Continue,
            Some(Verdict::Drop) => DecryptedFlowOutcome::Drop,
            Some(Verdict::AllowWarn(msg)) => {
                ctx.warnings.push(msg.clone());
                events::emit(events::Event::new(events::EventKind::PolicyWarning { message: msg, verdict: "allow" }));
                DecryptedFlowOutcome::Continue
            }
            Some(Verdict::DropWarn(msg)) => {
                ctx.warnings.push(msg.clone());
                events::emit(events::Event::new(events::EventKind::PolicyWarning { message: msg, verdict: "drop" }));
                DecryptedFlowOutcome::Drop
            }
            None => match pair.default_policy {
                crate::zones::DefaultPolicy::Allow => DecryptedFlowOutcome::Continue,
                _ => DecryptedFlowOutcome::Drop,
            },
        }
    }
}

fn endpoints_for_direction(meta: &SessionMeta, direction: Direction) -> (SocketAddr, SocketAddr) {
    match direction {
        Direction::ClientToServer => (meta.peer, meta.server),
        Direction::ServerToClient => (meta.server, meta.peer),
    }
}

fn ip_version_for(ip: IpAddr) -> IpVer {
    match ip {
        IpAddr::V4(_) => IpVer::V4,
        IpAddr::V6(_) => IpVer::V6,
    }
}

fn merge_dpi_context(current: &mut DpiContext, mut next: DpiContext, src_port: u16, dst_port: u16) {
    if next.tls_sni.is_none() {
        next.tls_sni = current.tls_sni.clone();
    }
    if next.http_host.is_none() {
        next.http_host = current.http_host.clone();
    }
    next.decrypted = true;
    next.src_port = next.src_port.or(Some(src_port));
    next.dst_port = next.dst_port.or(Some(dst_port));
    *current = next;
}

fn match_to_dpi(matched: &IpsSignatureMatch, blocked: bool) -> IpsMatch {
    IpsMatch {
        signature_name: matched.name.clone(),
        severity: matched.severity.as_str().to_string(),
        blocked,
    }
}

async fn dns_eval_context(
    dnssec: Option<&Arc<dyn DnssecProvider>>,
    dpi: &DpiContext,
) -> Option<DnsEvalContext> {
    if dpi.app_proto != Some(AppProto::Dns) {
        return None;
    }
    let domain = dpi.dns_query_name.clone()?;
    let qtype = dpi.dns_query_type;
    let provider = Arc::clone(dnssec?);

    let status = if provider.check_domain_in_spawn_blocking_context() {
        tokio::task::spawn_blocking(move || provider.check_domain(&domain, qtype).status)
            .await
            .ok()
    } else {
        Some(provider.check_domain(&domain, qtype).status)
    }?;

    Some(DnsEvalContext {
        dnssec_status: Some(status),
    })
}
