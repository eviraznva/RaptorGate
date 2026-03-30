use std::sync::Arc;
use std::time::SystemTime;

use ouroboros::self_referencing;
use etherparse::{err::packet, SlicedPacket};

use crate::dpi::DpiContext;

#[self_referencing]
#[derive(Debug)]
pub struct PacketContext {
    pub src_interface: Arc<str>,
    pub warnings: Vec<String>,
    pub arrival_time: SystemTime,
    pub raw: Vec<u8>,
    #[borrows(raw)]
    #[covariant]
    pub sliced_packet: SlicedPacket<'this>,
    
    pub dpi_ctx: Option<DpiContext>,
}

impl PacketContext {
    pub fn from_raw(raw: Vec<u8>, src_interface: Arc<str>) -> Result<Self, packet::SliceError> {
        PacketContextTryBuilder {
            src_interface,
            warnings: Vec::new(),
            arrival_time: SystemTime::now(),
            raw,
            sliced_packet_builder: |raw| SlicedPacket::from_ethernet(raw),
            dpi_ctx: None,
        }
        .try_build()
    }
}
