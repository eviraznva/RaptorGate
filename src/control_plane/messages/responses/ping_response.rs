use bytes::{Bytes, BytesMut};

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::ipc::ipc_message::{ensure_consumed, put_varlong, read_varlong, IpcMessage, IpcResponseMessage};

/// Payload odpowiedzi `PING`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResponse {
    pub timestamp_ms: u64,
    pub peer_timestamp_ms: u64,
}

impl IpcMessage for PingResponse {
    const OPCODE: IpcOpcode = IpcOpcode::Ping;
    const KIND: IpcFrameKind = IpcFrameKind::Response;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        let mut bytes = BytesMut::new();
        
        put_varlong(&mut bytes, self.timestamp_ms);
        put_varlong(&mut bytes, self.peer_timestamp_ms);
        
        Ok(bytes.freeze())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        let mut cursor = payload;
        
        let timestamp_ms = read_varlong(&mut cursor, "timestamp_ms")?;
        let peer_timestamp_ms = read_varlong(&mut cursor, "peer_timestamp_ms")?;
        
        ensure_consumed(cursor)?;
        
        Ok(Self {
            timestamp_ms,
            peer_timestamp_ms,
        })
    }
}

impl IpcResponseMessage for PingResponse {}