/// Błędy związane z kodowaniem, dekodowaniem i odczytem ramki IPC.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum IpcFrameError {
    #[error("IPC payload is too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("I/O error while processing IPC frame: {kind:?}")]
    Io { kind: std::io::ErrorKind },
    #[error("failed to read field `{field}`")]
    TruncatedField { field: &'static str },
    #[error("declared payload length ({declared}) exceeds available bytes ({available})")]
    IncompletePayload { declared: usize, available: usize },
    #[error("invalid IPC frame kind: {0}")]
    InvalidKind(u32),
    #[error("invalid IPC frame flags mask: 0x{0:X}")]
    InvalidFlags(u32),
}
