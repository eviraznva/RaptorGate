use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::errors::ipc_frame_error::IpcFrameError;
use crate::control_plane::errors::ipc_client_error::IpcClientError;

/// Błędy wysokopoziomowego, asynchronicznego endpointu IPC.
#[derive(thiserror::Error, Debug)]
pub enum AsyncIpcEndpointError {
    #[error(transparent)]
    Transport(#[from] IpcClientError),
    
    #[error(transparent)]
    Frame(#[from] IpcFrameError),
    
    #[error(transparent)]
    Payload(#[from] PayloadError),
    
    #[error("invalid IPC magic: expected 0x{expected:X}, got 0x{found:X}")]
    InvalidMagic { expected: u32, found: u32 },
    
    #[error("unsupported IPC version: expected {expected}, got {found}")]
    UnsupportedVersion { expected: u32, found: u32 },
    
    #[error("unexpected IPC frame kind: expected {expected:?}, got {found:?}")]
    UnexpectedKind {
        expected: IpcFrameKind,
        found: IpcFrameKind,
    },
    
    #[error("unexpected IPC opcode: expected {expected:?}, got {found:?}")]
    UnexpectedOpcode {
        expected: IpcOpcode,
        found: IpcOpcode,
    },
    
    #[error("unexpected IPC status for event frame: {0:?}")]
    UnexpectedStatus(IpcStatus),
    
    #[error("event frame must use request_id = 0, got {0}")]
    InvalidRequestId(u64),
}
