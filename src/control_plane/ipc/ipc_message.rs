use bytes::{Bytes, BytesMut};

use crate::control_plane::types::varint::VarInt;
use crate::control_plane::types::varlong::VarLong;
use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;

/// Bazowy trait dla każdej typowanej wiadomości IPC.
pub trait IpcMessage: Sized {
    const OPCODE: IpcOpcode;
    const KIND: IpcFrameKind;

    fn encode_payload(&self) -> Result<Bytes, PayloadError>;
    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError>;
}

/// Marker dla wiadomości typu request.
pub trait IpcRequestMessage: IpcMessage {}

/// Marker dla wiadomości typu response.
pub trait IpcResponseMessage: IpcMessage {}

/// Marker dla wiadomości typu event.
pub trait IpcEventMessage: IpcMessage {}

pub fn put_varint(bytes: &mut BytesMut, value: u32) {
    let mut buf = [0u8; VarInt::MAX_LEN];
    
    bytes.extend_from_slice(VarInt::new(value).encode_into(&mut buf));
}

pub fn put_varlong(bytes: &mut BytesMut, value: u64) {
    let mut buf = [0u8; VarLong::MAX_LEN];
    
    bytes.extend_from_slice(VarLong::new(value).encode_into(&mut buf));
}

pub fn put_bool(bytes: &mut BytesMut, value: bool) {
    put_varint(bytes, u32::from(value));
}

pub fn put_string(bytes: &mut BytesMut, value: &str) {
    put_varint(bytes, value.len() as u32);
    
    bytes.extend_from_slice(value.as_bytes());
}

pub fn put_bytes(bytes: &mut BytesMut, value: &[u8]) {
    put_varint(bytes, value.len() as u32);
    
    bytes.extend_from_slice(value);
}

pub fn read_varint(cursor: &mut &[u8], field: &'static str) -> Result<u32, PayloadError> {
    VarInt::decode_cursor(cursor).map(VarInt::get).ok_or(PayloadError::TruncatedField { field })
}

pub fn read_varlong(cursor: &mut &[u8], field: &'static str) -> Result<u64, PayloadError> {
    VarLong::decode_cursor(cursor).map(VarLong::get).ok_or(PayloadError::TruncatedField { field })
}

pub fn read_bool(cursor: &mut &[u8], field: &'static str) -> Result<bool, PayloadError> {
    match read_varint(cursor, field)? {
        0 => Ok(false),
        1 => Ok(true),
        value => Err(PayloadError::InvalidBool { field, value }),
    }
}

pub fn read_string(cursor: &mut &[u8], field: &'static str) -> Result<String, PayloadError> {
    let bytes = read_bytes(cursor, field)?;
    
    String::from_utf8(bytes).map_err(|_| PayloadError::InvalidUtf8 { field })
}

pub fn read_bytes(cursor: &mut &[u8], field: &'static str) -> Result<Vec<u8>, PayloadError> {
    let len = read_varint(cursor, field)? as usize;
    
    if cursor.len() < len {
        return Err(PayloadError::TruncatedField { field });
    }

    let bytes = cursor[..len].to_vec();
    
    *cursor = &cursor[len..];
    
    Ok(bytes)
}

pub fn ensure_consumed(cursor: &[u8]) -> Result<(), PayloadError> {
    if cursor.is_empty() {
        Ok(())
    } else {
        Err(PayloadError::TrailingBytes {
            remaining: cursor.len(),
        })
    }
}