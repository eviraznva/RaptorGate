use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use prost_types::Timestamp;
use std::sync::OnceLock;
use tokio::{select, sync::mpsc, time::interval};
use tokio_stream::wrappers::ReceiverStream;

use crate::data_plane::tcp_session_tracker::EndpointIdentifier;
use crate::proto::events as proto;
use crate::proto::services::backend_event_service_client::BackendEventServiceClient;
use crate::tls::inspection_relay::{Direction, InspectionMode};

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

const CHANNEL_CAPACITY: usize = 1024;
const FLUSH_INTERVAL_MS: u64 = 500;
const MAX_BATCH_SIZE: usize = 64;
const OVERFLOW_CAPACITY: usize = 512;
const RECONNECT_INTERVAL_SECS: u64 = 2;

static EVENT_TX: OnceLock<mpsc::Sender<Event>> = OnceLock::new();
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

struct BackendConnection {
    tx: mpsc::Sender<proto::Event>,
}

impl BackendConnection {
    /// Returns false if the gRPC task has died (receiver dropped).
    async fn send(&self, event: proto::Event) -> bool {
        tracing::trace!(
            event = "event_bus.dispatch.started",
            kind = ?event.kind,
            "sending event to backend stream"
        );

        self.tx.send(event).await.is_ok()
    }
}

async fn try_connect(socket_path: &str) -> Result<BackendConnection, tonic::transport::Error> {
    let socket_path = socket_path.to_owned();

    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
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
            tracing::warn!(
                event = "event_bus.backend_stream.ended",
                error = %e,
                "BackendEventService stream ended"
            );
        }
        // when this task returns, `rx` is dropped → `tx.send()` will fail
        // → the event loop detects it and sets backend = None
    });

    Ok(BackendConnection { tx })
}

pub fn emit(event: Event) {
    if let Some(tx) = EVENT_TX.get()
        && tx.try_send(event).is_err() {
            DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
        }
}

pub async fn init_event_system(socket_path: String) {
    let (tx, mut rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
    EVENT_TX.set(tx).unwrap_or_else(|_| panic!("event queue already initialised"));

    let mut backend: Option<BackendConnection> = None;
    let mut buffer: Vec<Event> = Vec::new();
    let mut flush_tick = interval(Duration::from_millis(FLUSH_INTERVAL_MS));
    let mut reconnect_interval = interval(Duration::from_secs(RECONNECT_INTERVAL_SECS));

    // Skip the first tick immediately
    reconnect_interval.tick().await;

    loop {
        select! {
            Some(event) = rx.recv() => {
                handle_incoming(event, &mut buffer, &mut backend).await;
            }
            _ = flush_tick.tick() => {
                flush_batch(&mut buffer, &mut backend).await;
            }
            _ = reconnect_interval.tick(), if backend.is_none() => {
                attempt_reconnect(&socket_path, &mut backend, &mut buffer).await;
            }
        }
    }
}

async fn handle_incoming(event: Event, buffer: &mut Vec<Event>, backend: &mut Option<BackendConnection>) {
    if event.kind.is_immediate() {
        flush_batch(buffer, backend).await;
        dispatch(event, backend, buffer).await;
    } else {
        buffer.push(event);
        if buffer.len() >= MAX_BATCH_SIZE {
            flush_batch(buffer, backend).await;
        }
    }
}

async fn flush_batch(buffer: &mut Vec<Event>, backend: &mut Option<BackendConnection>) {
    if backend.is_none() {
        return;
    }

    let batch = std::mem::take(buffer);

    for event in batch {
        dispatch(event, backend, buffer).await;
    }
}

async fn dispatch(event: Event, backend: &mut Option<BackendConnection>, buffer: &mut Vec<Event>) {
    match backend {
        Some(conn) => {
            if !conn.send(event.into()).await {
                tracing::warn!(
                    event = "event_bus.backend_connection.lost",
                    dropped_events = DROPPED_EVENTS.load(Ordering::Relaxed),
                    "backend connection lost, will reconnect"
                );
                *backend = None;
                DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
            }
        }

        None => {
            if buffer.len() < OVERFLOW_CAPACITY {
                tracing::trace!(
                    event = "event_bus.buffered",
                    kind = ?event.kind,
                    buffered_events = buffer.len(),
                    "no backend connection, buffering event"
                );
                buffer.push(event);
            } else {
                let dropped_events = DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    event = "event_bus.event_dropped",
                    kind = ?event.kind,
                    buffered_events = buffer.len(),
                    dropped_events,
                    "overflow buffer full, event dropped"
                );
            }
        }
    }
}

async fn attempt_reconnect(
    socket_path: &str,
    backend: &mut Option<BackendConnection>,
    buffer: &mut Vec<Event>,
) {
    let mut attempted_paths = vec![socket_path.to_string()];
    if socket_path.ends_with("/event.sock") {
        attempted_paths.push(socket_path.replacen("/event.sock", "/firewall.sock", 1));
    }

    let mut last_error = None;

    for attempted_socket_path in attempted_paths {
        match try_connect(&attempted_socket_path).await {
            Ok(conn) => {
                tracing::info!(
                    event = "event_bus.backend_connected",
                    socket_path = attempted_socket_path,
                    configured_socket_path = socket_path,
                    buffered_events = buffer.len(),
                    dropped_events = DROPPED_EVENTS.load(Ordering::Relaxed),
                    "reconnected to backend"
                );
                *backend = Some(conn);

                emit(Event::new(EventKind::EventBusConnectedEvent {}));
                flush_batch(buffer, backend).await;
                return;
            }
            Err(err) => {
                last_error = Some((attempted_socket_path, err));
            }
        }
    }

    if let Some((attempted_socket_path, err)) = last_error {
        tracing::warn!(
            event = "event_bus.backend_reconnect.failed",
            socket_path,
            attempted_socket_path,
            error = ?err,
            "reconnect attempt failed"
        );
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

#[derive(Debug)]
pub enum EventKind {
    TcpSessionEstabilished { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpSessionRemoved { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpConnectionRejected { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpSessionAbortedMidClose { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpSessionEnteredTimeWait { src: EndpointIdentifier, dst: EndpointIdentifier },
    TunDeviceSwapped { old_device: String, new_device: String, old_address: String, new_address: String },
    SnifferConfigChanged { old_interfaces: Vec<String>, new_interfaces: Vec<String>, old_timeout: Duration, new_timeout: Duration },
    TlsInterceptStarted { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, tls_version: Option<String> },
    TlsHandshakeComplete { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, alpn: Option<String>, tls_version: Option<String> },
    TlsSessionClosed { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, bytes_up: u64, bytes_down: u64 },
    InboundTlsInterceptStarted { peer: SocketAddr, server: SocketAddr, sni: Option<String>, common_name: String, tls_version: Option<String> },
    InboundTlsHandshakeComplete { peer: SocketAddr, server: SocketAddr, sni: Option<String>, alpn: Option<String>, tls_version: Option<String> },
    InboundTlsSessionClosed { peer: SocketAddr, server: SocketAddr, sni: Option<String>, bytes_up: u64, bytes_down: u64 },
    DecryptedTrafficClassified { peer: SocketAddr, server: SocketAddr, sni: Option<String>, app_proto: String, http_version: Option<String>, direction: Direction, mode: InspectionMode },
    DecryptedIpsMatch { peer: SocketAddr, server: SocketAddr, sni: Option<String>, signature_name: String, severity: String, blocked: bool, direction: Direction, mode: InspectionMode, log_id: String },
    TlsUntrustedCertDetected { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, domain: String, tls_version: Option<String> },
    TlsBypassApplied { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, domain: String, tls_version: Option<String> },
    InboundTlsBypassApplied { peer: SocketAddr, server: SocketAddr, sni: Option<String>, tls_version: Option<String> },
    PinningFailureDetected { peer: SocketAddr, dst: SocketAddr, sni: String, tls_version: Option<String> },
    PinningAutoBypassActivated { source_ip: IpAddr, domain: String, reason: String },
    TlsHandshakeFailed { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, tls_version: Option<String>, stage: HandshakeStage, reason: String, mode: InspectionMode },
    EchAttemptDetected { source_ip: Option<IpAddr>, domain: String, origin: EchOrigin, action: EchAction },
    IpsSignatureMatched {
        signature_id: String,
        signature_name: String,
        category: String,
        severity: String,
        action: String,
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
        transport_protocol: String,
        app_protocol: String,
        interface: String,
        payload_length: u32,
    },
    EventBusConnectedEvent {}
}

impl EventKind {
    pub const fn is_immediate(&self) -> bool {
        use EventKind as E;
        match self {
            E::TcpSessionEstabilished { .. }
            | E::TcpSessionRemoved { .. }
            | E::TcpConnectionRejected { .. }
            | E::TcpSessionAbortedMidClose { .. }
            | E::TcpSessionEnteredTimeWait { .. }
            | E::TunDeviceSwapped { .. }
            | E::SnifferConfigChanged { .. }
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
            | E::EchAttemptDetected { .. }
            | E::IpsSignatureMatched { .. }
            | E::EventBusConnectedEvent { .. } => true,
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

fn duration_to_proto(d: Duration) -> prost_types::Duration {
    prost_types::Duration {
        #[allow(clippy::cast_possible_wrap)]
        seconds: d.as_secs() as i64,
        #[allow(clippy::cast_possible_wrap)]
        nanos:   d.subsec_nanos() as i32,
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
                EventKind::TcpSessionEnteredTimeWait { src, dst } =>
                    Item::TcpSessionEnteredTimewait(proto::TcpSessionEnteredTimeWaitEvent {
                        src: Some(src.into()),
                        dst: Some(dst.into()),
                    }),

                EventKind::TunDeviceSwapped { old_device, new_device, old_address, new_address } =>
                    Item::TunDeviceSwapped(proto::TunDeviceSwappedEvent {
                        old_device,
                        new_device,
                        old_address,
                        new_address,
                    }),
                EventKind::SnifferConfigChanged { old_interfaces, new_interfaces, old_timeout, new_timeout } =>
                    Item::SnifferConfigChanged(proto::SnifferConfigChangedEvent {
                        old_interfaces,
                        new_interfaces,
                        old_timeout: Some(duration_to_proto(old_timeout)),
                        new_timeout: Some(duration_to_proto(new_timeout)),
                    }),
                EventKind::TlsInterceptStarted { peer, dst, sni, tls_version } =>
                    Item::TlsInterceptStarted(proto::TlsInterceptStartedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        dst_ip: dst.ip().to_string(),
                        dst_port: u32::from(dst.port()),
                        sni: sni.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::TlsHandshakeComplete { peer, dst, sni, alpn, tls_version } =>
                    Item::TlsHandshakeComplete(proto::TlsHandshakeCompleteEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        dst_ip: dst.ip().to_string(),
                        dst_port: u32::from(dst.port()),
                        sni: sni.unwrap_or_default(),
                        alpn: alpn.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::TlsSessionClosed { peer, dst, sni, bytes_up, bytes_down } =>
                    Item::TlsSessionClosed(proto::TlsSessionClosedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        dst_ip: dst.ip().to_string(),
                        dst_port: u32::from(dst.port()),
                        sni: sni.unwrap_or_default(),
                        bytes_up,
                        bytes_down,
                    }),
                EventKind::InboundTlsInterceptStarted { peer, server, sni, common_name, tls_version } =>
                    Item::InboundTlsInterceptStarted(proto::InboundTlsInterceptStartedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        server_ip: server.ip().to_string(),
                        server_port: u32::from(server.port()),
                        sni: sni.unwrap_or_default(),
                        common_name,
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::InboundTlsHandshakeComplete { peer, server, sni, alpn, tls_version } =>
                    Item::InboundTlsHandshakeComplete(proto::InboundTlsHandshakeCompleteEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        server_ip: server.ip().to_string(),
                        server_port: u32::from(server.port()),
                        sni: sni.unwrap_or_default(),
                        alpn: alpn.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::InboundTlsSessionClosed { peer, server, sni, bytes_up, bytes_down } =>
                    Item::InboundTlsSessionClosed(proto::InboundTlsSessionClosedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        server_ip: server.ip().to_string(),
                        server_port: u32::from(server.port()),
                        sni: sni.unwrap_or_default(),
                        bytes_up,
                        bytes_down,
                    }),
                EventKind::DecryptedTrafficClassified { peer, server, sni, app_proto, http_version, direction, mode } =>
                    Item::DecryptedTrafficClassified(proto::DecryptedTrafficClassifiedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        server_ip: server.ip().to_string(),
                        server_port: u32::from(server.port()),
                        sni: sni.unwrap_or_default(),
                        app_proto,
                        http_version: http_version.unwrap_or_default(),
                        direction: format!("{direction:?}"),
                        mode: format!("{mode:?}"),
                    }),
                EventKind::DecryptedIpsMatch { peer, server, sni, signature_name, severity, blocked, direction, mode, log_id } =>
                    Item::DecryptedIpsMatch(proto::DecryptedIpsMatchEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        server_ip: server.ip().to_string(),
                        server_port: u32::from(server.port()),
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
                        peer_port: u32::from(peer.port()),
                        dst_ip: dst.ip().to_string(),
                        dst_port: u32::from(dst.port()),
                        sni: sni.unwrap_or_default(),
                        domain,
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::TlsBypassApplied { peer, dst, sni, domain, tls_version } =>
                    Item::TlsBypassApplied(proto::TlsBypassAppliedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        dst_ip: dst.ip().to_string(),
                        dst_port: u32::from(dst.port()),
                        sni: sni.unwrap_or_default(),
                        domain,
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::InboundTlsBypassApplied { peer, server, sni, tls_version } =>
                    Item::InboundTlsBypassApplied(proto::InboundTlsBypassAppliedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        server_ip: server.ip().to_string(),
                        server_port: u32::from(server.port()),
                        sni: sni.unwrap_or_default(),
                        tls_version: tls_version.unwrap_or_default(),
                    }),
                EventKind::PinningFailureDetected { peer, dst, sni, tls_version } =>
                    Item::PinningFailureDetected(proto::PinningFailureDetectedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: u32::from(peer.port()),
                        dst_ip: dst.ip().to_string(),
                        dst_port: u32::from(dst.port()),
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
                        peer_port: u32::from(peer.port()),
                        dst_ip: dst.ip().to_string(),
                        dst_port: u32::from(dst.port()),
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
                EventKind::IpsSignatureMatched {
                    signature_id,
                    signature_name,
                    category,
                    severity,
                    action,
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    transport_protocol,
                    app_protocol,
                    interface,
                    payload_length,
                } => Item::IpsSignatureMatched(proto::IpsSignatureMatchedEvent {
                    signature_id,
                    signature_name,
                    category,
                    severity,
                    action,
                    src_ip,
                    src_port: u32::from(src_port),
                    dst_ip,
                    dst_port: u32::from(dst_port),
                    transport_protocol,
                    app_protocol,
                    interface,
                    payload_length,
                }),
                EventKind::EventBusConnectedEvent { .. } => Item::EventBusConnected(proto::EventBusConnectedEvent {})
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
