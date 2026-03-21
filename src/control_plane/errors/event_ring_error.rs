use crate::control_plane::errors::payload_error::PayloadError;

/// Błędy dodawania eventów do kolejki firewalla.
#[derive(Debug, thiserror::Error)]
pub enum EventRingError {
    #[error(transparent)]
    Encode(#[from] PayloadError),

    #[error("event queue is full")]
    Full,

    #[error("event queue is closed")]
    Closed,
}