use bytes::Bytes;
use tracing::trace;

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::ipc::ipc_message::{ensure_consumed, IpcMessage, IpcRequestMessage};

/// Pusty payload żądania listy interfejsów.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GetNetworkInterfacesRequest;

impl IpcMessage for GetNetworkInterfacesRequest {
    const OPCODE: IpcOpcode = IpcOpcode::GetNetworkInterfaces;
    const KIND: IpcFrameKind = IpcFrameKind::Request;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        trace!("Encoding GET_NETWORK_INTERFACES request payload");
        
        Ok(Bytes::new())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        trace!(payload_len = payload.len(), "Decoding GET_NETWORK_INTERFACES request payload");
        
        ensure_consumed(payload)?;
        
        Ok(Self)
    }
}

impl IpcRequestMessage for GetNetworkInterfacesRequest {}
