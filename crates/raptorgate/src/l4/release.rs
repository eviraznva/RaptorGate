use crate::data_plane::packet_context::{PacketContext, PacketId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    SessionTerminated,
    SessionClosed,
    PolicyDenied,
    StageDropped,
}

#[derive(Debug)]
pub enum ReleaseAction {
    Forward { packet: PacketContext },
    Drop { packet_id: PacketId, reason: DropReason },
}
