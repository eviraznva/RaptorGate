use bytes::{Bytes, BytesMut};

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;

use crate::control_plane::ipc::ipc_message::{
    FirewallMode, IpcEventMessage, IpcMessage,
    ensure_consumed, put_varint, put_varlong, read_varint, read_varlong
};

/// Payload eventu `HEARTBEAT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatEvent {
    pub timestamp_ms: u64,
    pub mode: FirewallMode,
    pub loaded_revision_id: u64,
    pub policy_hash: u64,
    pub uptime_sec: u64,
    pub last_error_code: u32,
}

impl IpcMessage for HeartbeatEvent {
    const OPCODE: IpcOpcode = IpcOpcode::Heartbeat;
    const KIND: IpcFrameKind = IpcFrameKind::Event;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        let mut bytes = BytesMut::new();
        
        put_varlong(&mut bytes, self.timestamp_ms);
        self.mode.encode_into(&mut bytes);
        
        put_varlong(&mut bytes, self.loaded_revision_id);
        put_varlong(&mut bytes, self.policy_hash);
        put_varlong(&mut bytes, self.uptime_sec);
        put_varint(&mut bytes, self.last_error_code);
        
        Ok(bytes.freeze())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        let mut cursor = payload;
        
        let timestamp_ms = read_varlong(&mut cursor, "timestamp_ms")?;
        let mode = FirewallMode::decode(&mut cursor, "mode")?;
        let loaded_revision_id = read_varlong(&mut cursor, "loaded_revision_id")?;
        let policy_hash = read_varlong(&mut cursor, "policy_hash")?;
        let uptime_sec = read_varlong(&mut cursor, "uptime_sec")?;
        let last_error_code = read_varint(&mut cursor, "last_error_code")?;
        
        ensure_consumed(cursor)?;
        
        Ok(Self {
            timestamp_ms,
            mode,
            loaded_revision_id,
            policy_hash,
            uptime_sec,
            last_error_code,
        })
    }
}

impl IpcEventMessage for HeartbeatEvent {}