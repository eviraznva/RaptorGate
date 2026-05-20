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
pub struct L4Emit {
    pub dir: Direction,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Outcome {
    Continue,
    Forward(Vec<PacketId>),
    Drop(Vec<PacketId>),
    Emit(Vec<L4Emit>),
    ForwardAndEmit { forward: Vec<PacketId>, emit: Vec<L4Emit> },
    Terminate { reason: TerminateReason, reset: bool },
}

#[tonic::async_trait]
pub trait L4Stage: Send {
    type Ctx: Send;

    fn protocol(&self) -> AppProto;

    async fn on_session_open(&mut self, ctx: &mut Self::Ctx) -> L4Outcome;

    async fn on_bytes(
        &mut self,
        ctx: &mut Self::Ctx,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome;

    async fn drain(&mut self, _ctx: &mut Self::Ctx) -> L4Outcome {
        L4Outcome::Continue
    }

    async fn on_session_close(&mut self, ctx: &mut Self::Ctx, reason: CloseReason);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingStage {
        byte_hits: u32,
    }

    impl CountingStage {
        fn new() -> Self {
            Self { byte_hits: 0 }
        }
    }

    #[tonic::async_trait]
    impl L4Stage for CountingStage {
        type Ctx = ();

        fn protocol(&self) -> AppProto {
            AppProto::Any
        }

        async fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
            L4Outcome::Continue
        }

        async fn on_bytes(
            &mut self,
            (): &mut Self::Ctx,
            packet_id: PacketId,
            _dir: Direction,
            _tcp_payload_start_seq: u32,
            _payload: &[u8],
        ) -> L4Outcome {
            self.byte_hits += 1;
            L4Outcome::Forward(vec![packet_id])
        }

        async fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) {}
    }

    #[tokio::test]
    async fn counting_stage_forwards_packet_id() {
        let mut st = CountingStage::new();
        let mut ctx = ();
        let id = PacketId::next();
        let out = st.on_bytes(&mut ctx, id, Direction::Original, 0, b"test").await;
        assert_eq!(st.byte_hits, 1);
        assert_eq!(out, L4Outcome::Forward(vec![id]));
    }
}
