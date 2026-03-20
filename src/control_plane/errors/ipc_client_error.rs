use crate::control_plane::errors::ipc_frame_error::IpcFrameError;

/// Błędy warstwy transportowej klienta IPC.
#[derive(thiserror::Error, Debug)]
pub enum IpcClientError {
    #[error("failed to connect to IPC socket: {0}")]
    Connect(#[source] std::io::Error),
    #[error("IPC client I/O error: {0}")]
    Io(#[source] std::io::Error),
    #[error("IPC stream ended while reading field `{field}`")]
    EndOfStream { field: &'static str },
    #[error(transparent)]
    Frame(#[from] IpcFrameError),
}
