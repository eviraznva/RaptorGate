use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, SystemTime};

use prost_types::Timestamp;
use tokio::{select, sync::mpsc, time::interval};
use tokio_stream::wrappers::ReceiverStream;

use crate::data_plane::tcp_session_tracker::EndpointIdentifier;
use crate::proto::events as proto;
use crate::proto::services::backend_event_service_client::BackendEventServiceClient;

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
            tracing::warn!(error = %e, "BackendEventService stream ended");
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
                tracing::warn!("backend connection lost, will reconnect");
                *backend = None;
                DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
            }
        }

        None => {
            if buffer.len() < OVERFLOW_CAPACITY {
                tracing::trace!(kind = ?event.kind, "no backend connection, buffering event");
                buffer.push(event);
            } else {
                DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(kind = ?event.kind, "overflow buffer full, event dropped");
            }
        }
    }
}

async fn attempt_reconnect(
    socket_path: &str,
    backend: &mut Option<BackendConnection>,
    buffer: &mut Vec<Event>,
) {
    match try_connect(socket_path).await {
        Ok(conn) => {
            tracing::info!("reconnected to backend");
            *backend = Some(conn);

            emit(Event::new(EventKind::EventBusConnectedEvent {}));
            flush_batch(buffer, backend).await;
        }
        Err(e) => {
            tracing::warn!(error = ?e, "reconnect attempt failed");
        }
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
            | E::EventBusConnectedEvent { .. }
            | E::SnifferConfigChanged { .. } => true,
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
