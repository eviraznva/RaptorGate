use bytes::Bytes;
use tokio::sync::mpsc;

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::ipc::ipc_message::IpcEventMessage;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
use crate::control_plane::errors::event_ring_error::EventRingError;

#[derive(Debug)]
pub struct QueuedEvent {
    opcode: IpcOpcode,
    flags: IpcFrameFlags,
    payload: Bytes,
}

impl QueuedEvent {
    pub fn opcode(&self) -> IpcOpcode {
        self.opcode
    }

    pub fn flags(&self) -> IpcFrameFlags {
        self.flags
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    fn from_message<E>(event: E, flags: IpcFrameFlags) -> Result<Self, PayloadError> where 
        E: IpcEventMessage
    {
        Ok(Self {
            opcode: E::OPCODE,
            flags,
            payload: event.encode_payload()?,
        })
    }
}

/// Klonowalny uchwyt do dodawania eventów z różnych wątków.
#[derive(Clone)]
pub struct EventRingHandle {
    tx: mpsc::Sender<QueuedEvent>,
}

impl EventRingHandle {
    pub fn new(tx: mpsc::Sender<QueuedEvent>) -> Self {
        Self { tx }
    }

    /// Dodaje typowany event do kolejki wysyłkowej.
    pub fn push<E>(&self, event: E) -> Result<(), EventRingError> where E: IpcEventMessage,
    {
        self.push_with_flags(event, IpcFrameFlags::NONE)
    }

    /// Dodaje typowany event do kolejki wysyłkowej z jawnie podanymi flagami.
    pub fn push_with_flags<E>(&self, event: E, flags: IpcFrameFlags) -> Result<(), EventRingError>
        where E: IpcEventMessage
    {
        let event = QueuedEvent::from_message(event, flags)?;

        match self.tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(EventRingError::Full),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(EventRingError::Closed),
        }
    }
}

pub fn channel(capacity: usize) -> (EventRingHandle, mpsc::Receiver<QueuedEvent>) {
    let (tx, rx) = mpsc::channel(capacity);
    
    (EventRingHandle::new(tx), rx)
}

#[cfg(test)]
mod event_ring_tests {
    use super::{EventRingError, channel};
    use crate::control_plane::types::ipc_opcode::IpcOpcode;
    use crate::control_plane::types::firewall_mode::FirewallMode;
    use crate::control_plane::types::ipc_frame_flags::IpcFrameFlags;
    use crate::control_plane::messages::events::heartbeat_event::HeartbeatEvent;

    #[tokio::test]
    async fn push_enqueues_encoded_event() {
        let (handle, mut rx) = channel(4);

        handle
            .push_with_flags(
                HeartbeatEvent {
                    timestamp_ms: 1,
                    mode: FirewallMode::Normal,
                    loaded_revision_id: 2,
                    policy_hash: 3,
                    uptime_sec: 4,
                    last_error_code: 5,
                },
                IpcFrameFlags::CRITICAL,
            ).unwrap();

        let queued = rx.recv().await.unwrap();

        assert_eq!(queued.opcode(), IpcOpcode::Heartbeat);
        assert_eq!(queued.flags(), IpcFrameFlags::CRITICAL);
        assert!(!queued.payload().is_empty());
    }

    #[test]
    fn push_returns_full_when_queue_is_full() {
        let (handle, _rx) = channel(1);

        handle
            .push(
                HeartbeatEvent {
                    timestamp_ms: 1,
                    mode: FirewallMode::Normal,
                    loaded_revision_id: 2,
                    policy_hash: 3,
                    uptime_sec: 4,
                    last_error_code: 5,
                },
            ).unwrap();

        let err = handle
            .push(
                HeartbeatEvent {
                    timestamp_ms: 6,
                    mode: FirewallMode::Degraded,
                    loaded_revision_id: 7,
                    policy_hash: 8,
                    uptime_sec: 9,
                    last_error_code: 10,
                },
            ).unwrap_err();

        assert!(matches!(err, EventRingError::Full));
    }
}
