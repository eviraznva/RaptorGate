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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDispositionOutcome {
    Forward,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketDispositionEvent {
    pub packet_id: PacketId,
    pub outcome: PacketDispositionOutcome,
    pub drop_reason: Option<DropReason>,
}
