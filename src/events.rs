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

#[derive(Debug)]
pub enum EventKind {
    TcpSessionEstabilished { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpSessionRemoved { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpConnectionRejected { src: EndpointIdentifier, dst: EndpointIdentifier },
    TcpSessionAbortedMidClose { src: EndpointIdentifier, dst: EndpointIdentifier },
    TlsInterceptStarted { peer: SocketAddr, dst: SocketAddr, sni: Option<String> },
    TlsHandshakeComplete { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, alpn: Option<String> },
    TlsSessionClosed { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, bytes_up: u64, bytes_down: u64 },
    InboundTlsInterceptStarted { peer: SocketAddr, server: SocketAddr, sni: Option<String>, common_name: String },
    InboundTlsHandshakeComplete { peer: SocketAddr, server: SocketAddr, sni: Option<String>, alpn: Option<String> },
    InboundTlsSessionClosed { peer: SocketAddr, server: SocketAddr, sni: Option<String>, bytes_up: u64, bytes_down: u64 },
    DecryptedTrafficClassified { peer: SocketAddr, server: SocketAddr, sni: Option<String>, app_proto: String, direction: Direction, mode: InspectionMode },
    DecryptedIpsMatch { peer: SocketAddr, server: SocketAddr, sni: Option<String>, signature_name: String, severity: String, blocked: bool, direction: Direction, mode: InspectionMode },
    TlsUntrustedCertDetected { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, domain: String },
    TlsBypassApplied { peer: SocketAddr, dst: SocketAddr, sni: Option<String>, domain: String },
    InboundTlsBypassApplied { peer: SocketAddr, server: SocketAddr, sni: Option<String> },
    PinningFailureDetected { peer: SocketAddr, dst: SocketAddr, sni: String },
    PinningAutoBypassActivated { source_ip: IpAddr, domain: String, reason: String },
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
            | E::PinningAutoBypassActivated { .. } => true,
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
                EventKind::TlsInterceptStarted { peer, dst, sni } =>
                    Item::TlsInterceptStarted(proto::TlsInterceptStartedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                    }),
                EventKind::TlsHandshakeComplete { peer, dst, sni, alpn } =>
                    Item::TlsHandshakeComplete(proto::TlsHandshakeCompleteEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        alpn: alpn.unwrap_or_default(),
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
                EventKind::InboundTlsInterceptStarted { peer, server, sni, common_name } =>
                    Item::InboundTlsInterceptStarted(proto::InboundTlsInterceptStartedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                        common_name,
                    }),
                EventKind::InboundTlsHandshakeComplete { peer, server, sni, alpn } =>
                    Item::InboundTlsHandshakeComplete(proto::InboundTlsHandshakeCompleteEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                        alpn: alpn.unwrap_or_default(),
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
                EventKind::DecryptedIpsMatch { peer, server, sni, signature_name, severity, blocked, direction, mode } =>
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
                    }),
                EventKind::TlsUntrustedCertDetected { peer, dst, sni, domain } =>
                    Item::TlsUntrustedCertDetected(proto::TlsUntrustedCertDetectedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        domain,
                    }),
                EventKind::TlsBypassApplied { peer, dst, sni, domain } =>
                    Item::TlsBypassApplied(proto::TlsBypassAppliedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni: sni.unwrap_or_default(),
                        domain,
                    }),
                EventKind::InboundTlsBypassApplied { peer, server, sni } =>
                    Item::InboundTlsBypassApplied(proto::InboundTlsBypassAppliedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        server_ip: server.ip().to_string(),
                        server_port: server.port() as u32,
                        sni: sni.unwrap_or_default(),
                    }),
                EventKind::PinningFailureDetected { peer, dst, sni } =>
                    Item::PinningFailureDetected(proto::PinningFailureDetectedEvent {
                        peer_ip: peer.ip().to_string(),
                        peer_port: peer.port() as u32,
                        dst_ip: dst.ip().to_string(),
                        dst_port: dst.port() as u32,
                        sni,
                    }),
                EventKind::PinningAutoBypassActivated { source_ip, domain, reason } =>
                    Item::PinningAutoBypassActivated(proto::PinningAutoBypassActivatedEvent {
                        source_ip: source_ip.to_string(),
                        domain,
                        reason,
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
