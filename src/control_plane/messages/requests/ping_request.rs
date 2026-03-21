use tracing::trace;
use bytes::{Bytes, BytesMut};

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;

use crate::control_plane::ipc::ipc_message::{
    IpcMessage, IpcRequestMessage,
    ensure_consumed, put_varlong, read_varlong
};

/// Payload żądania `PING`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingRequest {
    pub timestamp_ms: u64,
}

impl IpcMessage for PingRequest {
    const OPCODE: IpcOpcode = IpcOpcode::Ping;
    const KIND: IpcFrameKind = IpcFrameKind::Request;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        trace!(timestamp_ms = self.timestamp_ms, "Encoding PING request payload");
        
        let mut bytes = BytesMut::new();
        
        put_varlong(&mut bytes, self.timestamp_ms);
        
        Ok(bytes.freeze())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        trace!(payload_len = payload.len(), "Decoding PING request payload");
        
        let mut cursor = payload;
        
        let timestamp_ms = read_varlong(&mut cursor, "timestamp_ms")?;
        
        ensure_consumed(cursor)?;
        
        let request = Self { timestamp_ms };

        trace!(timestamp_ms = request.timestamp_ms, "Decoded PING request payload");

        Ok(request)
    }
}

impl IpcRequestMessage for PingRequest {}
