use tracing::trace;
use bytes::{Bytes, BytesMut};

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::types::firewall_mode::FirewallMode;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;

use crate::control_plane::ipc::ipc_message::{
    IpcMessage, IpcResponseMessage,
    ensure_consumed, put_varint, put_varlong, read_varint, read_varlong
};

/// Payload odpowiedzi `GET_STATUS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetStatusResponse {
    pub mode: FirewallMode,
    pub loaded_revision_id: u64,
    pub policy_hash: u64,
    pub uptime_sec: u64,
    pub last_error_code: u32,
}

impl IpcMessage for GetStatusResponse {
    const OPCODE: IpcOpcode = IpcOpcode::GetStatus;
    const KIND: IpcFrameKind = IpcFrameKind::Response;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        trace!(
            mode = ?self.mode,
            loaded_revision_id = self.loaded_revision_id,
            policy_hash = self.policy_hash,
            uptime_sec = self.uptime_sec,
            last_error_code = self.last_error_code,
            "Encoding GET_STATUS response payload"
        );
        
        let mut bytes = BytesMut::new();
        
        self.mode.encode_into(&mut bytes);
        
        put_varlong(&mut bytes, self.loaded_revision_id);
        put_varlong(&mut bytes, self.policy_hash);
        put_varlong(&mut bytes, self.uptime_sec);
        put_varint(&mut bytes, self.last_error_code);
        
        Ok(bytes.freeze())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        trace!(payload_len = payload.len(), "Decoding GET_STATUS response payload");
        
        let mut cursor = payload;
        
        let mode = FirewallMode::decode(&mut cursor, "mode")?;
        let loaded_revision_id = read_varlong(&mut cursor, "loaded_revision_id")?;
        let policy_hash = read_varlong(&mut cursor, "policy_hash")?;
        let uptime_sec = read_varlong(&mut cursor, "uptime_sec")?;
        let last_error_code = read_varint(&mut cursor, "last_error_code")?;
        
        ensure_consumed(cursor)?;
        
        let response = Self {
            mode,
            loaded_revision_id,
            policy_hash,
            uptime_sec,
            last_error_code,
        };

        trace!(
            mode = ?response.mode,
            loaded_revision_id = response.loaded_revision_id,
            policy_hash = response.policy_hash,
            uptime_sec = response.uptime_sec,
            last_error_code = response.last_error_code,
            "Decoded GET_STATUS response payload"
        );

        Ok(response)
    }
}

impl IpcResponseMessage for GetStatusResponse {}
