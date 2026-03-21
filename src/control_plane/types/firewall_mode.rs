use bytes::BytesMut;

use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::ipc::ipc_message::{put_varint, read_varint};

/// Tryb działania firewalla raportowany przez payloady statusowe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallMode {
    Normal = 1,
    Degraded = 2,
    Emergency = 3,
}

impl FirewallMode {
    pub(crate) fn encode_into(self, bytes: &mut BytesMut) {
        put_varint(bytes, self as u32);
    }

    pub(crate) fn decode(cursor: &mut &[u8], field: &'static str) -> Result<Self, PayloadError> {
        match read_varint(cursor, field)? {
            1 => Ok(Self::Normal),
            2 => Ok(Self::Degraded),
            3 => Ok(Self::Emergency),
            value => Err(PayloadError::InvalidEnumValue { field, value }),
        }
    }
}