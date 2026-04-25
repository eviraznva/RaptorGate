use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, anyhow};
use etherparse::{PacketBuilder, TransportSlice};
use tonic::async_trait;

use crate::data_plane::packet_context::PacketContext;
use crate::dpi::{DpiClassifier, DpiContext};
use crate::identity::{
    enforce, resolve_identity, EnforcementOutcome, IdentityContext, IdentityEnforcementConfig,
    IdentitySessionStore,
};
use crate::pipeline::{Stage, StageOutcome};
use crate::tls::inspection_relay::{Direction, SessionMeta};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionDisposition {
    Forward,
    Drop,
}

pub struct InspectionDecision {
    pub disposition: InspectionDisposition,
    pub ctx: DpiContext,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait DecryptedTrafficInspector: Send + Sync {
    async fn inspect(
        &self,
        payload: &[u8],
        seed_ctx: &DpiContext,
        direction: Direction,
        meta: &SessionMeta,
    ) -> InspectionDecision;

    fn close_session(&self, _meta: &SessionMeta) {}
}

pub struct NoopDecryptedInspector;

#[async_trait]
impl DecryptedTrafficInspector for NoopDecryptedInspector {
    async fn inspect(
        &self,
        payload: &[u8],
        seed_ctx: &DpiContext,
        _direction: Direction,
        _meta: &SessionMeta,
    ) -> InspectionDecision {
        InspectionDecision {
            disposition: InspectionDisposition::Forward,
            ctx: seed_ctx.clone(),
            payload: payload.to_vec(),
        }
    }
}

pub struct DecryptedChainInspector<P> {
    pipeline: P,
    dpi_classifier: Arc<DpiClassifier>,
    identity_sessions: Arc<IdentitySessionStore>,
    identity_enforcement: Arc<IdentityEnforcementConfig>,
}

impl<P> DecryptedChainInspector<P> {
    pub fn new(pipeline: P, dpi_classifier: Arc<DpiClassifier>) -> Self {
        Self::with_identity(
            pipeline,
            dpi_classifier,
            IdentitySessionStore::new_shared(),
            Arc::new(IdentityEnforcementConfig::default()),
        )
    }

    pub fn with_identity(
        pipeline: P,
        dpi_classifier: Arc<DpiClassifier>,
        identity_sessions: Arc<IdentitySessionStore>,
        identity_enforcement: Arc<IdentityEnforcementConfig>,
    ) -> Self {
        Self {
            pipeline,
            dpi_classifier,
            identity_sessions,
            identity_enforcement,
        }
    }
}

#[async_trait]
impl<P> DecryptedTrafficInspector for DecryptedChainInspector<P>
where
    P: Stage + Clone + Send + Sync + 'static,
{
    // Przepuszcza odszyfrowany payload przez wspolny chain jako syntetyczny pakiet TCP.
    async fn inspect(
        &self,
        payload: &[u8],
        seed_ctx: &DpiContext,
        direction: Direction,
        meta: &SessionMeta,
    ) -> InspectionDecision {
        let endpoints = endpoints_for_direction(meta, direction);
        let arrival_time = SystemTime::now();
        let identity = resolve_identity(&self.identity_sessions, meta.peer.ip(), arrival_time);
        let enforcement = enforce(&self.identity_enforcement, &identity);

        let mut packet_ctx = match build_packet_context(
            payload,
            seed_ctx,
            endpoints.0,
            endpoints.1,
            arrival_time,
            Some(identity),
        ) {
            Ok(ctx) => ctx,
            Err(err) => {
                tracing::warn!(
                    peer = %meta.peer,
                    server = %meta.server,
                    direction = ?direction,
                    error = %err,
                    "failed to synthesize decrypted packet context"
                );
                return InspectionDecision {
                    disposition: InspectionDisposition::Drop,
                    ctx: seed_ctx.clone(),
                    payload: Vec::new(),
                };
            }
        };

        if matches!(enforcement, EnforcementOutcome::Drop) {
            tracing::debug!(
                event = "identity.preauth.blocked",
                stage = "tls_decrypted_chain",
                peer = %meta.peer,
                server = %meta.server,
                direction = ?direction,
                "decrypted traffic blocked by identity pre-auth gate"
            );
            return InspectionDecision {
                disposition: InspectionDisposition::Drop,
                ctx: seed_ctx.clone(),
                payload: Vec::new(),
            };
        }

        let disposition = match self.pipeline.process(&mut packet_ctx).await {
            StageOutcome::Continue => InspectionDisposition::Forward,
            StageOutcome::Halt => InspectionDisposition::Drop,
        };

        let ctx = packet_ctx
            .borrow_dpi_ctx()
            .as_ref()
            .cloned()
            .unwrap_or_else(|| seed_ctx.clone());
        let payload = transport_payload(&packet_ctx);

        InspectionDecision {
            disposition,
            ctx,
            payload,
        }
    }

    fn close_session(&self, meta: &SessionMeta) {
        self.dpi_classifier.remove_session(
            meta.peer.ip(),
            meta.peer.port(),
            meta.server.ip(),
            meta.server.port(),
        );
        self.dpi_classifier.remove_session(
            meta.server.ip(),
            meta.server.port(),
            meta.peer.ip(),
            meta.peer.port(),
        );
    }
}

fn build_packet_context(
    payload: &[u8],
    seed_ctx: &DpiContext,
    src: SocketAddr,
    dst: SocketAddr,
    arrival_time: SystemTime,
    identity_ctx: Option<IdentityContext>,
) -> anyhow::Result<PacketContext> {
    let raw = build_tcp_packet(payload, src, dst)?;

    PacketContext::from_raw_full(
        raw,
        Arc::from("tls-decrypted"),
        Vec::new(),
        arrival_time,
        Some(seed_ctx.clone()),
        identity_ctx,
    )
    .context("failed to parse synthetic decrypted packet")
}

fn build_tcp_packet(payload: &[u8], src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Vec<u8>> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
            let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
                .ipv4(src_ip.octets(), dst_ip.octets(), 64)
                .tcp(src.port(), dst.port(), 0, 65_535);
            let mut raw = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut raw, payload)?;
            Ok(raw)
        }
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
            let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
                .ipv6(src_ip.octets(), dst_ip.octets(), 64)
                .tcp(src.port(), dst.port(), 0, 65_535);
            let mut raw = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut raw, payload)?;
            Ok(raw)
        }
        _ => Err(anyhow!("mixed IP families are not supported for decrypted inspection")),
    }
}

fn endpoints_for_direction(meta: &SessionMeta, direction: Direction) -> (SocketAddr, SocketAddr) {
    match direction {
        Direction::ClientToServer => (meta.peer, meta.server),
        Direction::ServerToClient => (meta.server, meta.peer),
    }
}

fn transport_payload(ctx: &PacketContext) -> Vec<u8> {
    match &ctx.borrow_sliced_packet().transport {
        Some(TransportSlice::Tcp(tcp)) => tcp.payload().to_vec(),
        Some(TransportSlice::Udp(udp)) => udp.payload().to_vec(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::Stage;
    use std::time::Duration;

    #[derive(Clone)]
    struct MarkingStage;

    impl Stage for MarkingStage {
        async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
            ctx.with_dpi_ctx_mut(|dpi| {
                if let Some(dpi) = dpi.as_mut() {
                    dpi.app_proto = Some(crate::dpi::AppProto::Http);
                }
            });
            StageOutcome::Continue
        }
    }

    fn test_meta() -> SessionMeta {
        SessionMeta {
            peer: "10.0.0.1:12345".parse().unwrap(),
            server: "10.0.0.2:443".parse().unwrap(),
            sni: Some("example.com".into()),
            mode: crate::tls::inspection_relay::InspectionMode::Outbound,
        }
    }

    fn identity_session() -> crate::identity::IdentitySession {
        let now = SystemTime::now();
        crate::identity::IdentitySession {
            session_id: "sess-1".into(),
            identity_user_id: "user-1".into(),
            username: "alice".into(),
            client_ip: "10.0.0.1".parse().unwrap(),
            authenticated_at: now,
            expires_at: now + Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn synthetic_packet_preserves_payload_and_seed_context() {
        let inspector = DecryptedChainInspector::new(MarkingStage, Arc::new(DpiClassifier::new()));
        let seed_ctx = DpiContext {
            decrypted: true,
            src_port: Some(12345),
            dst_port: Some(443),
            ..Default::default()
        };

        let decision = inspector
            .inspect(
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                &seed_ctx,
                Direction::ClientToServer,
                &test_meta(),
            )
            .await;

        assert_eq!(decision.disposition, InspectionDisposition::Forward);
        assert_eq!(decision.payload, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(decision.ctx.app_proto, Some(crate::dpi::AppProto::Http));
        assert!(decision.ctx.decrypted);
        assert_eq!(decision.ctx.src_port, Some(12345));
        assert_eq!(decision.ctx.dst_port, Some(443));
    }

    #[tokio::test]
    async fn synthetic_packet_blocks_missing_identity_when_required() {
        let inspector = DecryptedChainInspector::with_identity(
            MarkingStage,
            Arc::new(DpiClassifier::new()),
            crate::identity::IdentitySessionStore::new_shared(),
            Arc::new(crate::identity::IdentityEnforcementConfig::new(vec![
                "10.0.0.0/24".parse().unwrap(),
            ])),
        );
        let seed_ctx = DpiContext {
            decrypted: true,
            src_port: Some(12345),
            dst_port: Some(443),
            ..Default::default()
        };

        let decision = inspector
            .inspect(
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                &seed_ctx,
                Direction::ClientToServer,
                &test_meta(),
            )
            .await;

        assert_eq!(decision.disposition, InspectionDisposition::Drop);
        assert!(decision.payload.is_empty());
    }

    #[tokio::test]
    async fn synthetic_packet_allows_active_identity_when_required() {
        let store = crate::identity::IdentitySessionStore::new_shared();
        store.upsert(identity_session());
        let inspector = DecryptedChainInspector::with_identity(
            MarkingStage,
            Arc::new(DpiClassifier::new()),
            store,
            Arc::new(crate::identity::IdentityEnforcementConfig::new(vec![
                "10.0.0.0/24".parse().unwrap(),
            ])),
        );
        let seed_ctx = DpiContext {
            decrypted: true,
            src_port: Some(12345),
            dst_port: Some(443),
            ..Default::default()
        };

        let decision = inspector
            .inspect(
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                &seed_ctx,
                Direction::ClientToServer,
                &test_meta(),
            )
            .await;

        assert_eq!(decision.disposition, InspectionDisposition::Forward);
        assert_eq!(decision.ctx.app_proto, Some(crate::dpi::AppProto::Http));
    }
}
