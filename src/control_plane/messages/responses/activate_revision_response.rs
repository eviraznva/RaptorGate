use tracing::trace;
use bytes::{Bytes, BytesMut};

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;
use crate::control_plane::errors::payload_error::PayloadError;

use crate::control_plane::ipc::ipc_message::{
    IpcMessage, IpcResponseMessage,
    ensure_consumed, put_varint, put_varlong, read_varint, read_varlong
};

/// Payload odpowiedzi sukcesu po aktywacji rewizji polityki.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateRevisionResponse {
    pub loaded_revision_id: u64,
    pub policy_hash: u64,
    pub rule_count: u32,
}

impl IpcMessage for ActivateRevisionResponse {
    const OPCODE: IpcOpcode = IpcOpcode::ActivateRevision;
    const KIND: IpcFrameKind = IpcFrameKind::Response;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        trace!(
            loaded_revision_id = self.loaded_revision_id,
            policy_hash = self.policy_hash,
            rule_count = self.rule_count,
            "Encoding ACTIVATE_REVISION response payload"
        );
        
        let mut bytes = BytesMut::new();

        put_varlong(&mut bytes, self.loaded_revision_id);
        put_varlong(&mut bytes, self.policy_hash);
        put_varint(&mut bytes, self.rule_count);

        Ok(bytes.freeze())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        trace!(payload_len = payload.len(), "Decoding ACTIVATE_REVISION response payload");
        
        let mut cursor = payload;

        let loaded_revision_id = read_varlong(&mut cursor, "loaded_revision_id")?;
        let policy_hash = read_varlong(&mut cursor, "policy_hash")?;
        let rule_count = read_varint(&mut cursor, "rule_count")?;

        ensure_consumed(cursor)?;

        let response = Self {
            loaded_revision_id,
            policy_hash,
            rule_count,
        };

        trace!(
            loaded_revision_id = response.loaded_revision_id,
            policy_hash = response.policy_hash,
            rule_count = response.rule_count,
            "Decoded ACTIVATE_REVISION response payload"
        );

        Ok(response)
    }
}

impl IpcResponseMessage for ActivateRevisionResponse {}

#[cfg(test)]
mod activate_revision_response_tests {
    use super::ActivateRevisionResponse;
    use crate::control_plane::ipc::ipc_message::IpcMessage;

    #[test]
    fn roundtrip_payload() {
        let response = ActivateRevisionResponse {
            loaded_revision_id: 7,
            policy_hash: 0xabcdef,
            rule_count: 3,
        };
        
        let bytes = response.encode_payload().unwrap();

        assert_eq!(ActivateRevisionResponse::decode_payload(&bytes).unwrap(), response);
    }
}
