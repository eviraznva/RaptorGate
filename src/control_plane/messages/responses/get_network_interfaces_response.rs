use bytes::{Bytes, BytesMut};

use crate::control_plane::types::ipc_opcode::IpcOpcode;
use crate::control_plane::errors::payload_error::PayloadError;
use crate::control_plane::types::ipc_frame_kind::IpcFrameKind;

use crate::control_plane::ipc::ipc_message::{
    IpcMessage, IpcResponseMessage,
    ensure_consumed, put_bool, put_bytes, put_string,
    put_varint, read_bool, read_bytes, read_string, read_varint
};

/// Payload odpowiedzi `GET_NETWORK_INTERFACES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNetworkInterfacesResponse {
    pub interfaces: Vec<NetworkInterfaceEntry>,
}

/// Pojedynczy interfejs sieciowy raportowany przez firewalla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterfaceEntry {
    pub name: String,
    pub index: u32,
    pub is_up: bool,
    pub mtu: u32,
    pub mac: Vec<u8>,
    pub ips: Vec<String>,
}

impl IpcMessage for GetNetworkInterfacesResponse {
    const OPCODE: IpcOpcode = IpcOpcode::GetNetworkInterfaces;
    const KIND: IpcFrameKind = IpcFrameKind::Response;

    fn encode_payload(&self) -> Result<Bytes, PayloadError> {
        let mut bytes = BytesMut::new();

        put_varint(&mut bytes, self.interfaces.len() as u32);

        for interface in &self.interfaces {
            put_string(&mut bytes, &interface.name);
            put_varint(&mut bytes, interface.index);
            put_bool(&mut bytes, interface.is_up);
            put_varint(&mut bytes, interface.mtu);
            put_bytes(&mut bytes, &interface.mac);
            put_varint(&mut bytes, interface.ips.len() as u32);
            
            for ip in &interface.ips {
                put_string(&mut bytes, ip);
            }
        }

        Ok(bytes.freeze())
    }

    fn decode_payload(payload: &[u8]) -> Result<Self, PayloadError> {
        let mut cursor = payload;
        
        let count = read_varint(&mut cursor, "interfaces_count")? as usize;
        
        let mut interfaces = Vec::with_capacity(count);

        for _ in 0..count {
            let name = read_string(&mut cursor, "name")?;
            let index = read_varint(&mut cursor, "index")?;
            let is_up = read_bool(&mut cursor, "is_up")?;
            let mtu = read_varint(&mut cursor, "mtu")?;
            let mac = read_bytes(&mut cursor, "mac")?;
            let ip_count = read_varint(&mut cursor, "ip_count")? as usize;
            let mut ips = Vec::with_capacity(ip_count);

            for _ in 0..ip_count {
                ips.push(read_string(&mut cursor, "ip")?);
            }

            interfaces.push(NetworkInterfaceEntry {
                name,
                index,
                is_up,
                mtu,
                mac,
                ips,
            });
        }

        ensure_consumed(cursor)?;
        
        Ok(Self { interfaces })
    }
}

impl IpcResponseMessage for GetNetworkInterfacesResponse {}