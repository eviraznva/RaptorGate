use bytes::Bytes;
use tracing::trace;

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::ipc::ipc_message::{ensure_consumed, IpcMessage, IpcRequestMessage};

/// Pusty payload żądania statusu.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GetStatusRequest;

impl IpcMessage for GetStatusRequest {
    const OPCODE: IpcOpcode = IpcOpcode::GetStatus;
    const KIND: IpcFrameKind = IpcFrameKind::Request;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        trace!("Encoding GET_STATUS request payload");
        
        Ok(Bytes::new())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        trace!(payload_len = payload.len(), "Decoding GET_STATUS request payload");
        
        ensure_consumed(payload)?;
        
        Ok(Self)
    }
}

impl IpcRequestMessage for GetStatusRequest {}
