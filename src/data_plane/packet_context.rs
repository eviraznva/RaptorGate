use std::{rc::Rc, sync::Arc};

use etherparse::{SlicedPacket, err::packet};
use ouroboros::self_referencing;
use pcap::Packet;

#[self_referencing]
pub struct PacketContext {
    pub src_interface: Arc<str> , // we copy the interface name twice, maybe this is faster than a `String`

    raw: Vec<u8>,
    #[borrows(raw)]
    #[covariant]
    pub sliced_packet: SlicedPacket<'this>,

}

impl PacketContext {
    pub(super) fn from_captured_packet(packet: &Packet<'_>, src_interface: Arc<str>) -> Result<PacketContext, packet::SliceError> {

        PacketContextTryBuilder {
            raw: packet.data.to_vec(),
            sliced_packet_builder: |raw| SlicedPacket::from_ethernet(raw),
            src_interface,
        }.try_build()
    }
}
