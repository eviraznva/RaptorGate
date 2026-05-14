use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketContext;

use super::stage::{CloseReason, L4Outcome, L4Stage};

#[derive(Debug, Default)]
pub struct NoopTcpStage;

#[derive(Debug, Default)]
pub struct NoopUdpStage;

#[derive(Debug, Default)]
pub struct NoopIcmpStage;

impl L4Stage for NoopTcpStage {
    type Ctx = ();

    fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_packet(&mut self, (): &mut Self::Ctx, _packet: &mut PacketContext, _dir: Direction) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_bytes(
        &mut self,
        (): &mut Self::Ctx,
        _packet: &mut PacketContext,
        _dir: Direction,
        _payload: &[u8],
    ) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) -> L4Outcome {
        L4Outcome::Forward
    }
}

impl L4Stage for NoopUdpStage {
    type Ctx = ();

    fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_packet(&mut self, (): &mut Self::Ctx, _packet: &mut PacketContext, _dir: Direction) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_bytes(
        &mut self,
        (): &mut Self::Ctx,
        _packet: &mut PacketContext,
        _dir: Direction,
        _payload: &[u8],
    ) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) -> L4Outcome {
        L4Outcome::Forward
    }
}

impl L4Stage for NoopIcmpStage {
    type Ctx = ();

    fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_packet(&mut self, (): &mut Self::Ctx, _packet: &mut PacketContext, _dir: Direction) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_bytes(
        &mut self,
        (): &mut Self::Ctx,
        _packet: &mut PacketContext,
        _dir: Direction,
        _payload: &[u8],
    ) -> L4Outcome {
        L4Outcome::Forward
    }

    fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) -> L4Outcome {
        L4Outcome::Forward
    }
}
