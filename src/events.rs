use std::{net::IpAddr, sync::{atomic::{AtomicU64, Ordering}, OnceLock}, time::SystemTime};

use tokio::{select, sync::mpsc, time::{interval, Duration}};

use crate::data_plane::tcp_session_tracker::EndpointIdentifier;

const CHANNEL_CAPACITY: usize = 1024;
const FLUSH_INTERVAL_MS: u64 = 500;
const MAX_BATCH_SIZE: usize = 64;

static EVENT_TX: OnceLock<mpsc::Sender<Event>> = OnceLock::new();

pub fn emit(event: Event) {
    if let Some(tx) = EVENT_TX.get()
        && tx.try_send(event).is_err() {
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
}

#[derive(Debug)]
pub struct Event {
    emitted_at: SystemTime,
    kind: EventKind,
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
