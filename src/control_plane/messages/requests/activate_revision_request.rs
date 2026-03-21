use bytes::{Bytes, BytesMut};

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;

use crate::control_plane::ipc::ipc_message::{
    IpcMessage, IpcRequestMessage,
    ensure_consumed, put_varlong, read_varlong
};

/// Payload żądania aktywacji nowej rewizji polityki.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateRevisionRequest {
    pub revision_id: u64,
}

impl IpcMessage for ActivateRevisionRequest {
    const OPCODE: IpcOpcode = IpcOpcode::ActivateRevision;
    const KIND: IpcFrameKind = IpcFrameKind::Request;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        let mut bytes = BytesMut::new();

        put_varlong(&mut bytes, self.revision_id);

        Ok(bytes.freeze())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        let mut cursor = payload;

        let revision_id = read_varlong(&mut cursor, "revision_id")?;

        ensure_consumed(cursor)?;

        Ok(Self { revision_id })
    }
}

impl IpcRequestMessage for ActivateRevisionRequest {}

#[cfg(test)]
mod activate_revision_request_tests {
    use super::ActivateRevisionRequest;
    use crate::control_plane::ipc::ipc_message::IpcMessage;

    #[test]
    fn roundtrip_payload() {
        let request = ActivateRevisionRequest { revision_id: 42 };
        
        let bytes = request.encode_payload().unwrap();

        assert_eq!(ActivateRevisionRequest::decode_payload(&bytes).unwrap(), request);
    }
}
