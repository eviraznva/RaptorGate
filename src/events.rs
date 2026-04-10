use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::SystemTime;

use prost_types::Timestamp;
use tokio::{select, sync::mpsc, time::{interval, Duration}};
use tokio_stream::wrappers::ReceiverStream;

use std::net::{IpAddr, SocketAddr};

use crate::data_plane::tcp_session_tracker::EndpointIdentifier;
use crate::proto::events as proto;
use crate::proto::services::backend_event_service_client::BackendEventServiceClient;
use crate::tls::inspection_relay::{Direction, InspectionMode};

const CHANNEL_CAPACITY: usize = 1024;
const FLUSH_INTERVAL_MS: u64 = 500;
const MAX_BATCH_SIZE: usize = 64;

static EVENT_TX: OnceLock<mpsc::Sender<Event>> = OnceLock::new();
static BACKEND_SINK: OnceLock<BackendEventSink> = OnceLock::new();
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

pub struct BackendEventSink {
    tx: mpsc::Sender<proto::Event>,
}

impl BackendEventSink {
    pub async fn connect(socket_path: &str) -> Result<Self, tonic::transport::Error> {
        let socket_path = socket_path.to_owned();

        let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")? // TODO: get this from appconfig
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let path = socket_path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(&path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await?;

        let (tx, rx) = mpsc::channel::<proto::Event>(CHANNEL_CAPACITY);
        let mut client = BackendEventServiceClient::new(channel);

        tokio::spawn(async move {
            if let Err(e) = client.push_events(ReceiverStream::new(rx)).await {
                tracing::warn!(error = %e, "BackendEventService stream closed");
            }
        });

        Ok(Self { tx })
    }

    pub async fn forward(&self, event: proto::Event) {
        if self.tx.send(event).await.is_err() {
            DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("backend event sink closed, event dropped");
        }
    }
}

pub fn set_backend_sink(sink: BackendEventSink) {
    BACKEND_SINK.set(sink).unwrap_or_else(|_| panic!("backend sink already set"));
}

pub fn emit(event: Event) {
    if let Some(tx) = EVENT_TX.get()
        && tx.try_send(event).is_err() {
            DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("event queue full, event dropped");
        }
}

pub async fn init_event_queue() {
    let (tx, mut rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
    EVENT_TX.set(tx).unwrap_or_else(|_| panic!("event queue already initialised"));

    let mut buffer: Vec<Event> = Vec::new();
    let mut flush_tick = interval(Duration::from_millis(FLUSH_INTERVAL_MS));

    loop {
        select! {
            Some(event) = rx.recv() => {
                if event.kind.is_immediate() {
                    flush_batch(&mut buffer).await; // flush as we want to preserve event ordering
                    dispatch(event).await;
                } else {
                    buffer.push(event);
                    if buffer.len() >= MAX_BATCH_SIZE {
                        flush_batch(&mut buffer).await;
                    }
                }
            }
            _ = flush_tick.tick() => flush_batch(&mut buffer).await,
        }
    }
}

async fn flush_batch(buffer: &mut Vec<Event>) {
    if buffer.is_empty() { return; }
    for event in buffer.drain(..) {
        dispatch(event).await;
    }
}

async fn dispatch(event: Event) {
    tracing::debug!(kind = ?event.kind, "event dispatched");
    if let Some(sink) = BACKEND_SINK.get() {
        sink.forward(event.into()).await;
    }
}

#[derive(Debug)]
pub struct Event {
    pub emitted_at: SystemTime,
    pub kind: EventKind,
}

impl Event {
    pub fn new(kind: EventKind) -> Self {
        Self { emitted_at: SystemTime::now(), kind }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HandshakeStage {
    ClientHello,
    ServerHandshake,
    ClientFinished,
}

impl HandshakeStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientHello => "client_hello",
            Self::ServerHandshake => "server_handshake",
            Self::ClientFinished => "client_finished",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EchOrigin {
    DnsHttpsRecord,
    ClientHelloOuterSni,
}

impl EchOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DnsHttpsRecord => "dns_https_rr",
            Self::ClientHelloOuterSni => "client_hello_outer_sni",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EchAction {
    Logged,
    Stripped,
    Blocked,
}

impl EchAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Logged => "logged",
            Self::Stripped => "stripped",
            Self::Blocked => "blocked",
        }
    }
}

pub fn format_tls_version(raw: u16) -> String {
    match raw {
        0x0304 => "TLS1.3".to_string(),
        0x0303 => "TLS1.2".to_string(),
        0x0302 => "TLS1.1".to_string(),
        0x0301 => "TLS1.0".to_string(),
        0x0300 => "SSL3.0".to_string(),
        other => format!("0x{other:04x}"),
    }
}

#[derive(Debug)]
pub enum EventKind {
    TcpSessionEstabilished { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpSessionRemoved { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpConnectionRejected { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpSessionAbortedMidClose { src: EndpointIdentifier, dst: EndpointIdentifier },
    TlsInterceptStarted { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, tls_version: Option<String> },
    TlsHandshakeComplete { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, alpn: Option<String>, tls_version: Option<String> },
    TlsSessionClosed { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, bytes_up: u64, bytes_down: u64 },
    InboundTlsInterceptStarted { peer: SocketAddr, server: SocketAddr, sni: Option<String>, common_name: String, tls_version: Option<String> },
    InboundTlsHandshakeComplete { peer: SocketAddr, server: SocketAddr, sni: Option<String>, alpn: Option<String>, tls_version: Option<String> },
    InboundTlsSessionClosed { peer: SocketAddr, server: SocketAddr, sni: Option<String>, bytes_up: u64, bytes_down: u64 },
    DecryptedTrafficClassified { peer: SocketAddr, server: SocketAddr, sni: Option<String>, app_proto: String, direction: Direction, mode: InspectionMode },
    DecryptedIpsMatch { peer: SocketAddr, server: SocketAddr, sni: Option<String>, signature_name: String, severity: String, blocked: bool, direction: Direction, mode: InspectionMode, log_id: String },
    TlsUntrustedCertDetected { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, domain: String, tls_version: Option<String> },
    TlsBypassApplied { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, domain: String, tls_version: Option<String> },
    InboundTlsBypassApplied { peer: SocketAddr, server: SocketAddr, sni: Option<String>, tls_version: Option<String> },
    PinningFailureDetected { peer: SocketAddr, dst: SocketAddr, sni: String, tls_version: Option<String> },
    PinningAutoBypassActivated { source_ip: IpAddr, domain: String, reason: String },
    TlsHandshakeFailed { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, tls_version: Option<String>, stage: HandshakeStage, reason: String, mode: InspectionMode },
    EchAttemptDetected { source_ip: Option<IpAddr>, domain: String, origin: EchOrigin, action: EchAction },
}

impl EventKind {
    pub const fn is_immediate(&self) -> bool {
        use EventKind as E;
        match self {
            E::TcpSessionEstabilished { .. }
            | E::TcpSessionRemoved { .. }
            | E::TcpConnectionRejected { .. }
            | E::TcpSessionAbortedMidClose { .. }
            | E::TlsInterceptStarted { .. }
            | E::TlsHandshakeComplete { .. }
            | E::TlsSessionClosed { .. }
            | E::InboundTlsInterceptStarted { .. }
            | E::InboundTlsHandshakeComplete { .. }
            | E::InboundTlsSessionClosed { .. }
            | E::DecryptedTrafficClassified { .. }
            | E::DecryptedIpsMatch { .. }
            | E::TlsUntrustedCertDetected { .. }
            | E::TlsBypassApplied { .. }
            | E::InboundTlsBypassApplied { .. }
            | E::PinningFailureDetected { .. }
            | E::PinningAutoBypassActivated { .. }
            | E::TlsHandshakeFailed { .. }
            | E::EchAttemptDetected { .. } => true,
        }
    }
}

fn system_time_to_proto(t: SystemTime) -> Timestamp {
    let dur = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    Timestamp {
        #[allow(clippy::cast_possible_wrap)]
        seconds: dur.as_secs() as i64,
        #[allow(clippy::cast_possible_wrap)]
        nanos:   dur.subsec_nanos() as i32,
    }
}

impl From<EventKind> for proto::EventKind {
    fn from(kind: EventKind) -> Self {
        use proto::event_kind::Item;
        proto::EventKind {
            item: Some(match kind {
                EventKind::TcpSessionEstabilished { src, dst } =>
                    Item::TcpSessionEstablished(proto::TcpSessionEstablishedEvent {
                        src: Some(src.into()),
                        dst: Some(dst.into()),
                    }),
                EventKind::TcpSessionRemoved { src, dst } =>
                    Item::TcpSessionRemoved(proto::TcpSessionRemovedEvent {
                        src: Some(src.into()),
                        dst: Some(dst.into()),
                    }),
                EventKind::TcpConnectionRejected { src, dst } =>
                    Item::TcpConnectionRejected(proto::TcpConnectionRejectedEvent {
                        src: Some(src.into()),
                        dst: Some(dst.into()),
                    }),
                EventKind::TcpSessionAbortedMidClose { src, dst } =>
                    Item::TcpSessionAborted(proto::TcpSessionAbortedMidCloseEvent {
                        src: Some(src.into()),
                        dst: Some(dst.into()),
                    }),
                EventKind::TlsInterceptStarted { peer, dst, sni, tls_version } =>
                    Item::TlsInterceptStarted(proto::TlsInterceptStartedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::TlsHandshakeComplete { peer, dst, sni, alpn, tls_version } =>
                    Item::TlsHandshakeComplete(proto::TlsHandshakeCompleteEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        alpn: alpn.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::TlsSessionClosed { peer, dst, sni, bytes_up, bytes_down } =>
                    Item::TlsSessionClosed(proto::TlsSessionClosedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        bytes_up,
                        bytes_down,
                    }),
                EventKind::InboundTlsInterceptStarted { peer, server, sni, common_name, tls_version } =>
                    Item::InboundTlsInterceptStarted(proto::InboundTlsInterceptStartedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                        common_name,
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::InboundTlsHandshakeComplete { peer, server, sni, alpn, tls_version } =>
                    Item::InboundTlsHandshakeComplete(proto::InboundTlsHandshakeCompleteEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                        alpn: alpn.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::InboundTlsSessionClosed { peer, server, sni, bytes_up, bytes_down } =>
                    Item::InboundTlsSessionClosed(proto::InboundTlsSessionClosedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                        bytes_up,
                        bytes_down,
                    }),
                EventKind::DecryptedTrafficClassified { peer, server, sni, app_proto, direction, mode } =>
                    Item::DecryptedTrafficClassified(proto::DecryptedTrafficClassifiedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                        app_proto,
                        direction: format!("{direction:?}"),
                        mode: format!("{mode:?}"),
                    }),
                EventKind::DecryptedIpsMatch { peer, server, sni, signature_name, severity, blocked, direction, mode, log_id } =>
                    Item::DecryptedIpsMatch(proto::DecryptedIpsMatchEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                        signature_name,
                        severity,
                        blocked,
                        direction: format!("{direction:?}"),
                        mode: format!("{mode:?}"),
                        log_id,
                    }),
                EventKind::TlsUntrustedCertDetected { peer, dst, sni, domain, tls_version } =>
                    Item::TlsUntrustedCertDetected(proto::TlsUntrustedCertDetectedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        domain,
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::TlsBypassApplied { peer, dst, sni, domain, tls_version } =>
                    Item::TlsBypassApplied(proto::TlsBypassAppliedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        domain,
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::InboundTlsBypassApplied { peer, server, sni, tls_version } =>
                    Item::InboundTlsBypassApplied(proto::InboundTlsBypassAppliedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::PinningFailureDetected { peer, dst, sni, tls_version } =>
                    Item::PinningFailureDetected(proto::PinningFailureDetectedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni,
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::PinningAutoBypassActivated { source_ip, domain, reason } =>
                    Item::PinningAutoBypassActivated(proto::PinningAutoBypassActivatedEvent {
                        source_ip: source_ip.to_string(),
                        domain,
                        reason,
                    }),
                EventKind::TlsHandshakeFailed { peer, dst, sni, tls_version, stage, reason, mode } =>
                    Item::TlsHandshakeFailed(proto::TlsHandshakeFailedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                        stage: stage.as_str().to_string(),
                        reason,
                        mode: format!("{mode:?}"),
                    }),
                EventKind::EchAttemptDetected { source_ip, domain, origin, action } =>
                    Item::EchAttemptDetected(proto::EchAttemptDetectedEvent {
                        source_ip: source_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                        domain,
                        origin: origin.as_str().to_string(),
                        action: action.as_str().to_string(),
                    }),
            }),
        }
    }
}

impl From<Event> for proto::Event {
    fn from(event: Event) -> Self {
        proto::Event {
            emitted_at: Some(system_time_to_proto(event.emitted_at)),
            kind:       Some(event.kind.into()),
        }
    }
}
