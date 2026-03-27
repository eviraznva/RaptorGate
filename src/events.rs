use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::SystemTime;

use prost_types::Timestamp;
use tokio::{select, sync::mpsc, time::{interval, Duration}};

use crate::{data_plane::tcp_session_tracker::EndpointIdentifier, proto::events::event_kind::Item};
use crate::proto::events as proto;

const CHANNEL_CAPACITY: usize = 1024;
const FLUSH_INTERVAL_MS: u64 = 500;
const MAX_BATCH_SIZE: usize = 64;

static EVENT_TX: OnceLock<mpsc::Sender<Event>> = OnceLock::new();
static PROTO_TX: OnceLock<mpsc::Sender<proto::Event>> = OnceLock::new();
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

pub fn emit(event: Event) {
    if let Some(tx) = EVENT_TX.get()
        && tx.try_send(event).is_err() {
            DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("event queue full, event dropped");
        }
}

pub fn set_backend_channel(tx: mpsc::Sender<proto::Event>) {
    PROTO_TX.set(tx).unwrap_or_else(|_| panic!("backend channel already set"));
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
                    flush_batch(&mut buffer).await;
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
    if let Some(tx) = PROTO_TX.get() {
        let proto_event: proto::Event = event.into();
        let _ = tx.send(proto_event).await;
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
}

impl EventKind {
    pub const fn is_immediate(&self) -> bool {
        use EventKind as E;
        match self {
            E::TcpSessionEstabilished { .. }
            | E::TcpSessionRemoved { .. }
            | E::TcpConnectionRejected { .. }
            | E::TcpSessionAbortedMidClose { .. } => true,
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
