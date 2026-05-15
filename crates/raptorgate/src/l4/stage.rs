use crate::conntrack::observer::DestroyReason;
use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
pub use crate::dpi::AppProto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Finished,
    Timeout,
    Reset,
    Invalidated,
}

impl From<DestroyReason> for CloseReason {
    fn from(value: DestroyReason) -> Self {
        match value {
            DestroyReason::Timeout => CloseReason::Timeout,
            DestroyReason::Manual | DestroyReason::Replaced | DestroyReason::Shutdown => CloseReason::Finished,
            DestroyReason::InvalidatedByStage => CloseReason::Invalidated,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminateReason {
    StageRequested,
    SmtpPolicyDenied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Outcome {
    Continue,
    Forward(Vec<PacketId>),
    Terminate { reason: TerminateReason, reset: bool },
}

pub trait L4Stage: Send {
    type Ctx;

    fn protocol(&self) -> AppProto;

    fn on_session_open(&mut self, ctx: &mut Self::Ctx) -> L4Outcome;

    fn on_bytes(
        &mut self,
        ctx: &mut Self::Ctx,
        packet_id: PacketId,
        dir: Direction,
        payload: &[u8],
    ) -> L4Outcome;

    fn on_session_close(&mut self, ctx: &mut Self::Ctx, reason: CloseReason);
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::sync::Arc;

    struct CountingStage {
        byte_hits: u32,
    }

    impl CountingStage {
        fn new() -> Self {
            Self { byte_hits: 0 }
        }
    }

    impl L4Stage for CountingStage {
        type Ctx = ();

        fn protocol(&self) -> AppProto {
            AppProto::Any
        }

        fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
            L4Outcome::Continue
        }

        fn on_bytes(
            &mut self,
            (): &mut Self::Ctx,
            packet_id: PacketId,
            _dir: Direction,
            _payload: &[u8],
        ) -> L4Outcome {
            self.byte_hits += 1;
            L4Outcome::Forward(vec![packet_id])
        }

        fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) {}
    }

    #[test]
    fn counting_stage_forwards_packet_id() {
        let mut st = CountingStage::new();
        let mut ctx = ();
        let id = PacketId::next();
        let out = st.on_bytes(&mut ctx, id, Direction::Original, b"test");
        assert_eq!(st.byte_hits, 1);
        assert_eq!(out, L4Outcome::Forward(vec![id]));
    }
}
