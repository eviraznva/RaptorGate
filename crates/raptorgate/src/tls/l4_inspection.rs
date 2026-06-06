use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::parsers::tls::{parse_tls_client_hello, TlsParseResult};
use crate::dpi::{AppProto, DpiClassifier, DpiContext, TlsAction};
use crate::events::{self, Event, EventKind};
use crate::identity::{resolve_identity, IdentitySessionStore};
use crate::l4::context::SessionContext;
use crate::l4::http::HttpL4Stage;
use crate::l4::stage::{L4Outcome, TerminateReason};
use crate::l4::L4TcpEndpoint;
use crate::tls::cert_forger::CertForger;
use crate::tls::decrypted_flow::{DecryptedFlowContext, DecryptedFlowOutcome, DecryptedFlowPipeline};
use crate::tls::decryption_mirror::DecryptionMirror;
use crate::tls::decision_engine::TlsDecisionEngine;
use crate::tls::dual_session::{self, AcceptParams, ConnectParams};
use crate::tls::pinning_detector::PinningReason;
use crate::tls::rustls_config;
use crate::tls::session_meta::{Direction as TlsRelayDirection, InspectionMode, SessionMeta};
#[cfg(test)]
use crate::tls::ca_manager::CaManager;
#[cfg(test)]
use crate::tls::decryption_mirror::DecryptionMirrorConfig;
#[cfg(test)]
use crate::tls::decision_engine::EchTlsPolicy;
#[cfg(test)]
use crate::tls::pinning_detector::PinningConfig;
#[cfg(test)]
use crate::tls::server_key_store::ServerKeyStore;

const CLIENT_HELLO_PEEK_LIMIT: usize = 4096;
const RELAY_BUF_SIZE: usize = 16 * 1024;

pub struct TlsL4InspectionConfig {
    pub cert_forger: Arc<CertForger>,
    pub untrust_forger: Arc<CertForger>,
    pub decision_engine: Arc<TlsDecisionEngine>,
    pub decrypted_pipeline: DecryptedFlowPipeline,
    pub dpi_classifier: Arc<DpiClassifier>,
    pub identity_sessions: Arc<IdentitySessionStore>,
    pub decryption_mirror: Arc<DecryptionMirror>,
    #[cfg(test)]
    pub(crate) test_action_override: Option<TlsAction>,
}

pub struct TlsL4InspectionService {
    config: Arc<TlsL4InspectionConfig>,
    state: TlsL4State,
}

pub trait TlsPlaintextTarget {
    fn app_proto(&self) -> AppProto;
    fn inspect_plaintext(&mut self, ctx: &mut SessionContext, dir: Direction, payload: &[u8]) -> L4Outcome;
}

impl TlsPlaintextTarget for HttpL4Stage {
    fn app_proto(&self) -> AppProto {
        AppProto::Http
    }

    fn inspect_plaintext(&mut self, ctx: &mut SessionContext, _dir: Direction, payload: &[u8]) -> L4Outcome {
        HttpL4Stage::inspect_plaintext(self, ctx, payload);
        L4Outcome::Continue
    }
}

enum TlsL4State {
    Peeking {
        buffer: Vec<u8>,
        pending_ids: Vec<PacketId>,
    },
    Bypass,
    Blocked,
    Intercept(InterceptState),
}

struct InterceptState {
    handle: crate::l4::L4TcpEndpointHandle,
    events_rx: mpsc::UnboundedReceiver<TlsWorkerEvent>,
    meta: SessionMeta,
    mirror_sequence: u64,
}

enum TlsWorkerEvent {
    Plaintext {
        dir: Direction,
        payload: Vec<u8>,
        decision_tx: oneshot::Sender<PlaintextDecision>,
    },
    Finished,
    Failed(String),
}

enum PlaintextDecision {
    Forward(Vec<u8>),
    Drop,
}

struct TlsWorkerParams {
    config: Arc<TlsL4InspectionConfig>,
    endpoint: L4TcpEndpoint,
    server_addr: SocketAddr,
    source_ip: IpAddr,
    sni: Option<String>,
    client_alpn_protocols: Vec<Vec<u8>>,
}

impl TlsL4InspectionService {
    pub fn new(config: Arc<TlsL4InspectionConfig>) -> Self {
        Self {
            config,
            state: TlsL4State::Peeking {
                buffer: Vec::new(),
                pending_ids: Vec::new(),
            },
        }
    }

    pub async fn on_encrypted_bytes<A>(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        _tcp_payload_start_seq: u32,
        payload: &[u8],
        _app: &mut A,
    ) -> L4Outcome
    where
        A: TlsPlaintextTarget,
    {
        if payload.is_empty() {
            return L4Outcome::Forward(vec![packet_id]);
        }

        if matches!(self.state, TlsL4State::Peeking { .. }) {
            let previous = std::mem::replace(&mut self.state, TlsL4State::Blocked);
            let TlsL4State::Peeking { mut buffer, mut pending_ids } = previous else {
                unreachable!();
            };

                pending_ids.push(packet_id);
                buffer.extend_from_slice(payload);

                if !looks_like_tls_client_hello_prefix(&buffer) {
                    let ids = std::mem::take(&mut pending_ids);
                    self.state = TlsL4State::Bypass;
                    return L4Outcome::Forward(ids);
                }

                let Some(parsed) = parse_tls_client_hello(&buffer) else {
                    if buffer.len() >= CLIENT_HELLO_PEEK_LIMIT {
                        let ids = std::mem::take(&mut pending_ids);
                        self.state = TlsL4State::Bypass;
                        return L4Outcome::Forward(ids);
                    }
                    self.state = TlsL4State::Peeking { buffer, pending_ids };
                    return L4Outcome::Continue;
                };

                let action = decide_with_config(&self.config, ctx, &parsed);
                match action {
                    TlsAction::Bypass => {
                        let ids = std::mem::take(&mut pending_ids);
                        self.state = TlsL4State::Bypass;
                        return L4Outcome::Forward(ids);
                    }
                    TlsAction::Block => {
                        let ids = std::mem::take(&mut pending_ids);
                        self.state = TlsL4State::Blocked;
                        return L4Outcome::Drop(ids);
                    }
                    TlsAction::Intercept => {
                        let encrypted = std::mem::take(&mut buffer);
                        let ids = std::mem::take(&mut pending_ids);
                        match self.start_intercept(ctx, parsed, encrypted).await {
                            Ok(()) => return L4Outcome::Drop(ids),
                            Err(error) => {
                                tracing::warn!(error = %error, "tls l4 intercept startup failed");
                                self.state = TlsL4State::Blocked;
                                return L4Outcome::Terminate {
                                    reason: TerminateReason::StageRequested,
                                    reset: true,
                                };
                            }
                        }
                    }
                }
        }

        match &mut self.state {
            TlsL4State::Bypass => L4Outcome::Forward(vec![packet_id]),
            TlsL4State::Blocked => L4Outcome::Drop(vec![packet_id]),
            TlsL4State::Intercept(state) => {
                if dir == Direction::Original && let Err(error) = state.handle.admit(dir, payload.to_vec()).await {
                    tracing::warn!(error = %error, "tls l4 endpoint closed");
                    return L4Outcome::Terminate {
                        reason: TerminateReason::StageRequested,
                        reset: true,
                    };
                }
                L4Outcome::Drop(vec![packet_id])
            }
            TlsL4State::Peeking { .. } => unreachable!(),
        }
    }

    pub async fn drain<A>(&mut self, ctx: &mut SessionContext, app: &mut A) -> L4Outcome
    where
        A: TlsPlaintextTarget,
    {
        let mut emit = Vec::new();
        loop {
            let drained = match &mut self.state {
                TlsL4State::Intercept(state) => {
                    while let Some(item) = state.handle.try_next_emitted() {
                        emit.push(item);
                    }
                    match state.events_rx.try_recv() {
                        Ok(event) => Some(event),
                        Err(mpsc::error::TryRecvError::Empty) => None,
                        Err(mpsc::error::TryRecvError::Disconnected) => Some(TlsWorkerEvent::Finished),
                    }
                }
                _ => None,
            };

            let Some(event) = drained else {
                break;
            };

            match event {
                TlsWorkerEvent::Plaintext { dir, payload, decision_tx } => {
                    let decision = self.inspect_plaintext(ctx, app, dir, payload).await;
                    let blocked = matches!(decision, PlaintextDecision::Drop);
                    let _ = decision_tx.send(decision);
                    if blocked {
                        return L4Outcome::Terminate {
                            reason: TerminateReason::StageRequested,
                            reset: true,
                        };
                    }
                }
                TlsWorkerEvent::Finished => {
                    self.close_dpi_sessions(ctx);
                    break;
                }
                TlsWorkerEvent::Failed(reason) => {
                    tracing::warn!(reason = %reason, "tls l4 worker failed");
                    self.close_dpi_sessions(ctx);
                    return L4Outcome::Terminate {
                        reason: TerminateReason::StageRequested,
                        reset: true,
                    };
                }
            }
        }

        if emit.is_empty() {
            L4Outcome::Continue
        } else {
            L4Outcome::Emit(emit)
        }
    }

    pub fn on_session_close(&mut self, ctx: &SessionContext) {
        self.close_dpi_sessions(ctx);
    }

    async fn start_intercept(
        &mut self,
        ctx: &SessionContext,
        parsed: TlsParseResult,
        encrypted: Vec<u8>,
    ) -> anyhow::Result<()> {
        let (endpoint, handle) = L4TcpEndpoint::new();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let entry = ctx.entry();
        let server_addr = SocketAddr::new(entry.original.dst_ip, entry.original.dst_port);
        let meta = build_session_meta(ctx, parsed.sni.clone(), InspectionMode::Outbound);

        handle.admit(Direction::Original, encrypted).await?;

        let params = TlsWorkerParams {
            config: Arc::clone(&self.config),
            endpoint,
            server_addr,
            source_ip: entry.original.src_ip,
            sni: parsed.sni,
            client_alpn_protocols: parsed.alpn_protocols,
        };

        tokio::spawn(async move {
            if let Err(error) = run_tls_worker(params, events_tx.clone()).await {
                let _ = events_tx.send(TlsWorkerEvent::Failed(error.to_string()));
            }
        });

        self.state = TlsL4State::Intercept(InterceptState {
            handle,
            events_rx,
            meta,
            mirror_sequence: 0,
        });
        Ok(())
    }

    async fn inspect_plaintext<A>(
        &mut self,
        ctx: &mut SessionContext,
        app: &mut A,
        dir: Direction,
        payload: Vec<u8>,
    ) -> PlaintextDecision
    where
        A: TlsPlaintextTarget,
    {
        let (meta, sequence) = match &self.state {
            TlsL4State::Intercept(state) => (state.meta.clone(), state.mirror_sequence),
            _ => return PlaintextDecision::Drop,
        };
        let relay_dir = relay_direction(dir);
        let now = SystemTime::now();
        let identity = resolve_identity(&self.config.identity_sessions, meta.peer.ip(), now);
        let mut dpi = DpiContext {
            app_proto: Some(app.app_proto()),
            decrypted: true,
            ..Default::default()
        };
        set_ports_for_direction(&mut dpi, &meta, relay_dir);

        let mut decrypted = DecryptedFlowContext::new(
            payload,
            dpi,
            relay_dir,
            meta.clone(),
            now,
            Some(identity),
        );

        let outcome = self.config.decrypted_pipeline.process(&mut decrypted).await;
        if matches!(outcome, DecryptedFlowOutcome::Drop) {
            if !self.config.decryption_mirror.current_config().forwarded_only {
                self.config.decryption_mirror.record_data(
                    meta.session_id,
                    sequence,
                    relay_dir,
                    &meta,
                    &decrypted.payload,
                );
            }
            return PlaintextDecision::Drop;
        }

        if let L4Outcome::Terminate { .. } = app.inspect_plaintext(ctx, dir, &decrypted.payload) {
            return PlaintextDecision::Drop;
        }

        self.config.decryption_mirror.record_data(
            meta.session_id,
            sequence,
            relay_dir,
            &meta,
            &decrypted.payload,
        );
        if let TlsL4State::Intercept(state) = &mut self.state {
            state.mirror_sequence = state.mirror_sequence.saturating_add(1);
        }

        PlaintextDecision::Forward(decrypted.payload)
    }

    fn close_dpi_sessions(&self, ctx: &SessionContext) {
        let entry = ctx.entry();
        self.config.dpi_classifier.remove_session(
            entry.original.src_ip,
            entry.original.src_port,
            entry.original.dst_ip,
            entry.original.dst_port,
        );
        self.config.dpi_classifier.remove_session(
            entry.original.dst_ip,
            entry.original.dst_port,
            entry.original.src_ip,
            entry.original.src_port,
        );
        if let TlsL4State::Intercept(state) = &self.state {
            self.config.decryption_mirror.finish_session(state.meta.session_id);
        }
    }
}

async fn run_tls_worker(
    params: TlsWorkerParams,
    events_tx: mpsc::UnboundedSender<TlsWorkerEvent>,
) -> anyhow::Result<()> {
    let server_tcp = TcpStream::connect(params.server_addr)
        .await
        .with_context(|| format!("failed to connect to TLS upstream {}", params.server_addr))?;

    let inbound = params.config.decision_engine.server_key_store().get_entry_active(params.server_addr);
    let domain = params.sni.clone().unwrap_or_else(|| params.server_addr.ip().to_string());

    let (client_tls, server_tls, negotiated_alpn) = if let Some(inbound) = inbound {
        let client_config = rustls_config::build_client_config_no_verify_with_alpn(&params.client_alpn_protocols)?;
        let server_tls = dual_session::connect_to_server(ConnectParams {
            stream: server_tcp,
            client_config,
            server_name: domain.clone(),
        })
        .await?;
        let negotiated_alpn = server_tls.get_ref().1.alpn_protocol().map(|protocol| protocol.to_vec());
        let server_config = rustls_config::build_server_config_for_key_with_alpn(
            inbound.certified_key,
            &selected_alpn_protocols(negotiated_alpn.as_deref()),
        )?;
        let client_tls = dual_session::accept_client_tls(AcceptParams {
            stream: params.endpoint,
            server_config,
        })
        .await?;
        (client_tls, server_tls, negotiated_alpn)
    } else {
        let (client_config, trusted_flag) =
            rustls_config::build_client_config_recording_with_alpn(&params.client_alpn_protocols)?;
        let server_tls = dual_session::connect_to_server(ConnectParams {
            stream: server_tcp,
            client_config,
            server_name: domain.clone(),
        })
        .await?;
        let trusted = trusted_flag.load(std::sync::atomic::Ordering::Acquire);
        let extra_sans = dual_session::extract_peer_sans(&server_tls);
        let active_forger = if trusted {
            &params.config.cert_forger
        } else {
            &params.config.untrust_forger
        };
        let forged = active_forger.forge(&domain, &extra_sans)?;
        let certified_key = forged.to_certified_key()?;
        let negotiated_alpn = server_tls.get_ref().1.alpn_protocol().map(|protocol| protocol.to_vec());
        let server_config = rustls_config::build_server_config_for_key_with_alpn(
            certified_key,
            &selected_alpn_protocols(negotiated_alpn.as_deref()),
        )?;
        let client_tls = match dual_session::accept_client_tls(AcceptParams {
            stream: params.endpoint,
            server_config,
        })
        .await {
            Ok(client_tls) => client_tls,
            Err(error) => {
                let reason = decryption_failure_reason_from_accept_error(&error);
                let report = params.config.decision_engine.report_decryption_failure(
                    params.source_ip,
                    Some(params.server_addr.ip()),
                    params.server_addr.port(),
                    &domain,
                    reason.clone(),
                );
                events::emit(Event::new(EventKind::PinningFailureDetected {
                    peer: SocketAddr::new(params.source_ip, 0),
                    dst: params.server_addr,
                    sni: domain.clone(),
                    tls_version: None,
                }));
                if report.activated_exclusion {
                    events::emit(Event::new(EventKind::PinningAutoBypassActivated {
                        source_ip: params.source_ip,
                        domain: domain.clone(),
                        reason: reason.to_string(),
                    }));
                }
                return Err(error);
            }
        };
        (client_tls, server_tls, negotiated_alpn)
    };

    let _ = negotiated_alpn;
    let (client_read, client_write) = tokio::io::split(client_tls);
    let (server_read, server_write) = tokio::io::split(server_tls);
    let up_events = events_tx.clone();
    let down_events = events_tx.clone();

    let c2s = tokio::spawn(async move {
        relay_one_direction(client_read, server_write, Direction::Original, up_events).await;
    });
    let s2c = tokio::spawn(async move {
        relay_one_direction(server_read, client_write, Direction::Reply, down_events).await;
    });

    let _ = tokio::join!(c2s, s2c);
    let _ = events_tx.send(TlsWorkerEvent::Finished);
    Ok(())
}

fn decryption_failure_reason_from_accept_error(error: &anyhow::Error) -> PinningReason {
    for cause in error.chain() {
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            match io_error.kind() {
                std::io::ErrorKind::ConnectionReset => return PinningReason::TcpReset,
                std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe => return PinningReason::ConnectionClosedNoData,
                _ => {}
            }
            if let Some(rustls_error) = io_error.get_ref().and_then(|source| source.downcast_ref::<rustls::Error>())
                && let Some(reason) = decryption_failure_reason_from_rustls_error(rustls_error) {
                return reason;
            }
        }
        if let Some(rustls_error) = cause.downcast_ref::<rustls::Error>()
            && let Some(reason) = decryption_failure_reason_from_rustls_error(rustls_error) {
            return reason;
        }
    }
    PinningReason::TlsAlert {
        alert_description: error.to_string(),
    }
}

fn decryption_failure_reason_from_rustls_error(error: &rustls::Error) -> Option<PinningReason> {
    match error {
        rustls::Error::AlertReceived(alert) => Some(match alert {
            rustls::AlertDescription::BadCertificate
            | rustls::AlertDescription::CertificateUnknown
            | rustls::AlertDescription::BadCertificateHashValue => PinningReason::SuspectedPinnedCertificate,
            rustls::AlertDescription::CertificateRequired => PinningReason::ClientCertificateRequired,
            rustls::AlertDescription::ProtocolVersion
            | rustls::AlertDescription::InsufficientSecurity
            | rustls::AlertDescription::HandshakeFailure => PinningReason::UnsupportedTlsMode,
            _ => PinningReason::TlsAlert {
                alert_description: format!("{alert:?}"),
            },
        }),
        _ => None,
    }
}

async fn relay_one_direction<R, W>(
    mut reader: R,
    mut writer: W,
    dir: Direction,
    events_tx: mpsc::UnboundedSender<TlsWorkerEvent>,
)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; RELAY_BUF_SIZE];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                let _ = writer.shutdown().await;
                return;
            }
            Ok(n) => n,
            Err(_) => {
                let _ = writer.shutdown().await;
                return;
            }
        };

        let (decision_tx, decision_rx) = oneshot::channel();
        if events_tx
            .send(TlsWorkerEvent::Plaintext {
                dir,
                payload: buf[..n].to_vec(),
                decision_tx,
            })
            .is_err()
        {
            let _ = writer.shutdown().await;
            return;
        }

        match decision_rx.await {
            Ok(PlaintextDecision::Forward(payload)) => {
                if writer.write_all(&payload).await.is_err() {
                    let _ = writer.shutdown().await;
                    return;
                }
            }
            Ok(PlaintextDecision::Drop) | Err(_) => {
                let _ = writer.shutdown().await;
                return;
            }
        }
    }
}

fn looks_like_tls_client_hello_prefix(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return true;
    }
    buf[0] == 0x16 && buf[1] == 0x03 && (1..=4).contains(&buf[2])
}

fn decide_with_config(
    config: &TlsL4InspectionConfig,
    ctx: &SessionContext,
    parsed: &TlsParseResult,
) -> TlsAction {
    #[cfg(test)]
    if let Some(action) = config.test_action_override {
        return action;
    }

    let entry = ctx.entry();
    config.decision_engine.decide(
        parsed.sni.as_deref(),
        parsed.ech_detected,
        Some(entry.original.dst_ip),
        entry.original.dst_port,
        Some(entry.original.src_ip),
    )
}

fn build_session_meta(
    ctx: &SessionContext,
    sni: Option<String>,
    mode: InspectionMode,
) -> SessionMeta {
    let entry = ctx.entry();
    let path = entry.interface_path();
    SessionMeta {
        session_id: Uuid::now_v7(),
        peer: SocketAddr::new(entry.original.src_ip, entry.original.src_port),
        server: SocketAddr::new(entry.original.dst_ip, entry.original.dst_port),
        sni,
        client_side_interface: path.original_ingress.map(|value| value.to_string()),
        server_side_interface: path.reply_ingress.map(|value| value.to_string()),
        mode,
    }
}

fn relay_direction(dir: Direction) -> TlsRelayDirection {
    match dir {
        Direction::Original => TlsRelayDirection::ClientToServer,
        Direction::Reply => TlsRelayDirection::ServerToClient,
    }
}

fn set_ports_for_direction(dpi: &mut DpiContext, meta: &SessionMeta, dir: TlsRelayDirection) {
    match dir {
        TlsRelayDirection::ClientToServer => {
            dpi.src_port = Some(meta.peer.port());
            dpi.dst_port = Some(meta.server.port());
        }
        TlsRelayDirection::ServerToClient => {
            dpi.src_port = Some(meta.server.port());
            dpi.dst_port = Some(meta.peer.port());
        }
    }
}

fn selected_alpn_protocols(protocol: Option<&[u8]>) -> Vec<Vec<u8>> {
    protocol.map(|protocol| vec![protocol.to_vec()]).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::entry::ConntrackEntry;
    use crate::conntrack::proto::tcp::TcpProtoState;
    use crate::conntrack::proto::ProtoState;
    use crate::conntrack::tuple::{Direction, FlowTuple, Protocol};
    use crate::data_plane::packet_context::PacketId;
    use crate::l4::http::HttpL4Stage;
    use crate::l4::stage::L4Outcome;
    use crate::zones::resolver::ZoneResolver;
    use crate::zones::{DirectionalZonePairs, ResolvedZonePair, ZonePairId};
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair, SanType};
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

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

    fn test_session_context(dst_port: u16) -> crate::l4::SessionContext {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port,
            Protocol::Tcp,
        );
        let entry = Arc::new(ConntrackEntry::new(
            7,
            tuple,
            ProtoState::Tcp(TcpProtoState::default()),
            Duration::from_secs(60),
            0,
        ));
        crate::l4::SessionContext::open(entry, &StubZoneResolver)
    }

    fn tls_client_hello_for(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let entry_len = 1 + 2 + name.len();
        let ext_data_len = 2 + entry_len;
        let mut sni = Vec::new();
        sni.extend_from_slice(&0x0000u16.to_be_bytes());
        sni.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        sni.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]);
        ch_body.extend_from_slice(&[0u8; 32]);
        ch_body.push(0);
        ch_body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        ch_body.push(1);
        ch_body.push(0);
        ch_body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&sni);

        let mut handshake = Vec::new();
        handshake.push(1);
        let hs_len = ch_body.len() as u32;
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&ch_body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn test_service() -> TlsL4InspectionService {
        TlsL4InspectionService::new(Arc::new(TlsL4InspectionConfig::test_with_bypass_domains(&[])))
    }

    fn test_service_with_block_decision() -> TlsL4InspectionService {
        TlsL4InspectionService::new(Arc::new(TlsL4InspectionConfig::test_block_all()))
    }

    #[tokio::test]
    async fn service_forwards_empty_tcp_segment() {
        let mut service = test_service();
        let mut ctx = test_session_context(443);
        let packet_id = PacketId::next();

        let out = service.on_encrypted_bytes(
            &mut ctx,
            packet_id,
            Direction::Original,
            0,
            b"",
            &mut HttpL4Stage::new(),
        ).await;

        assert!(matches!(out, L4Outcome::Forward(ids) if ids == vec![packet_id]));
    }

    #[tokio::test]
    async fn service_bypasses_non_tls_payload() {
        let mut service = test_service();
        let mut ctx = test_session_context(443);
        let packet_id = PacketId::next();

        let out = service.on_encrypted_bytes(
            &mut ctx,
            packet_id,
            Direction::Original,
            0,
            b"GET / HTTP/1.1\r\n\r\n",
            &mut HttpL4Stage::new(),
        ).await;

        assert!(matches!(out, L4Outcome::Forward(ids) if ids == vec![packet_id]));
    }

    #[tokio::test]
    async fn service_drops_when_decision_engine_blocks() {
        let mut service = test_service_with_block_decision();
        let mut ctx = test_session_context(443);

        let out = service.on_encrypted_bytes(
            &mut ctx,
            PacketId::next(),
            Direction::Original,
            0,
            &tls_client_hello_for("blocked.example"),
            &mut HttpL4Stage::new(),
        ).await;

        assert!(matches!(out, L4Outcome::Terminate { .. } | L4Outcome::Drop(_)));
    }

    #[tokio::test]
    async fn worker_records_decryption_failure_on_client_close_before_tls() {
        let key = KeyPair::generate().unwrap();
        let mut cert_params = CertificateParams::default();
        cert_params.is_ca = IsCa::NoCa;
        cert_params
            .distinguished_name
            .push(DnType::CommonName, "pinned.example");
        cert_params.subject_alt_names = vec![SanType::DnsName(
            "pinned.example".to_string().try_into().unwrap(),
        )];
        let cert = cert_params.self_signed(&key).unwrap();
        let upstream_config = rustls_config::build_server_config_from_pem(&cert.pem(), &key.serialize_pem()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();

        let upstream = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = TlsAcceptor::from(upstream_config);
            let _tls = acceptor.accept(stream).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let mut config = TlsL4InspectionConfig::test_with_bypass_domains(&[]);
        let pki_dir = std::env::temp_dir()
            .join(uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string());
        std::fs::create_dir_all(&pki_dir).unwrap();
        let decision_engine = Arc::new(TlsDecisionEngine::new(
            &[],
            Arc::new(ServerKeyStore::new(pki_dir.to_str().unwrap())),
            EchTlsPolicy::default(),
            PinningConfig {
                failure_threshold: 1,
                ..PinningConfig::default()
            },
        ));
        config.decision_engine = Arc::clone(&decision_engine);
        let config = Arc::new(config);
        let (endpoint, handle) = L4TcpEndpoint::new();
        drop(handle);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let source_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let result = run_tls_worker(
            TlsWorkerParams {
                config,
                endpoint,
                server_addr: upstream_addr,
                source_ip,
                sni: Some("pinned.example".to_string()),
                client_alpn_protocols: Vec::new(),
            },
            events_tx,
        ).await;

        assert!(result.is_err());
        let detail = decision_engine
            .pinning_detector_arc()
            .decryption_exclusion_detail("pinned.example", Some(upstream_addr.ip()), upstream_addr.port())
            .unwrap();
        assert!(matches!(detail.reason, PinningReason::ConnectionClosedNoData));
        assert_eq!(detail.failure_count, 1);
        assert_eq!(detail.last_source_ip, source_ip);

        upstream.await.unwrap();
    }

    #[test]
    fn pinning_reason_classifies_tcp_reset() {
        let error = anyhow::Error::new(std::io::Error::new(ErrorKind::ConnectionReset, "client reset"));

        assert!(matches!(decryption_failure_reason_from_accept_error(&error), PinningReason::TcpReset));
    }

    #[test]
    fn decryption_failure_reason_classifies_bad_certificate_as_suspected_pinning() {
        let error = anyhow::Error::new(rustls::Error::AlertReceived(rustls::AlertDescription::BadCertificate));

        assert!(matches!(
            decryption_failure_reason_from_accept_error(&error),
            PinningReason::SuspectedPinnedCertificate
        ));
    }

    #[test]
    fn pinning_reason_classifies_closed_without_data() {
        let error = anyhow::Error::new(std::io::Error::new(ErrorKind::UnexpectedEof, "client closed"));

        assert!(matches!(decryption_failure_reason_from_accept_error(&error), PinningReason::ConnectionClosedNoData));
    }
}

#[cfg(test)]
impl TlsL4InspectionConfig {
    pub(crate) fn test_with_bypass_domains(domains: &[&str]) -> Self {
        Self::test_config(domains, None)
    }

    pub(crate) fn test_block_all() -> Self {
        Self::test_config(&[], Some(TlsAction::Block))
    }

    fn test_config(domains: &[&str], action: Option<TlsAction>) -> Self {
        let pki_dir = std::env::temp_dir()
            .join(uuid::Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext)).to_string());
        std::fs::create_dir_all(&pki_dir).unwrap();
        let ca = CaManager::init_ephemeral_for_tests().unwrap();
        let bypass_domains: Vec<String> = domains.iter().map(|domain| (*domain).to_string()).collect();
        Self {
            cert_forger: Arc::new(ca.cert_forger(16).unwrap()),
            untrust_forger: Arc::new(ca.untrust_cert_forger(16).unwrap()),
            decision_engine: Arc::new(TlsDecisionEngine::new(
                &bypass_domains,
                Arc::new(ServerKeyStore::new(pki_dir.to_str().unwrap())),
                EchTlsPolicy::default(),
                PinningConfig::default(),
            )),
            decrypted_pipeline: DecryptedFlowPipeline::new(Vec::new()),
            dpi_classifier: Arc::new(DpiClassifier::new()),
            identity_sessions: Arc::new(IdentitySessionStore::new()),
            decryption_mirror: Arc::new(DecryptionMirror::start(
                DecryptionMirrorConfig::default(),
                tokio_util::sync::CancellationToken::new(),
            )),
            test_action_override: action,
        }
    }
}
