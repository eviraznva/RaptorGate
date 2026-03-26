use std::sync::Arc;

use etherparse::{err::packet, SlicedPacket};
use ouroboros::self_referencing;

#[self_referencing]
#[derive(Debug)]
pub struct PacketContext {
    pub src_interface: Arc<str>,
    pub warnings: Vec<String>,
    pub raw: Vec<u8>,
    #[borrows(raw)]
    #[covariant]
    pub sliced_packet: SlicedPacket<'this>,
}

impl PacketContext {
    pub fn from_raw(raw: Vec<u8>, src_interface: Arc<str>) -> Result<Self, packet::SliceError> {
        PacketContextTryBuilder {
            src_interface,
            warnings: Vec::new(),
            raw,
            sliced_packet_builder: |raw| SlicedPacket::from_ethernet(raw),
        }
        .try_build()
    }
}
