use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Finished,
    Timeout,
    Reset,
    Invalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Outcome {
    Forward,
    Drop,
    BufferPacket,
    ForwardBuffered,
    TerminateSession,
}

pub trait L4Stage: Send {
    type Ctx;

    fn on_session_open(&mut self, ctx: &mut Self::Ctx) -> L4Outcome;

    fn on_packet(&mut self, ctx: &mut Self::Ctx, packet: &mut PacketContext, dir: Direction) -> L4Outcome;

    fn on_bytes(
        &mut self,
        ctx: &mut Self::Ctx,
        packet: &mut PacketContext,
        dir: Direction,
        payload: &[u8],
    ) -> L4Outcome;

    fn on_session_close(&mut self, ctx: &mut Self::Ctx, reason: CloseReason) -> L4Outcome;
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::sync::Arc;

    struct CountingStage {
        packet_hits: u32,
    }

    impl CountingStage {
        fn new() -> Self {
            Self { packet_hits: 0 }
        }
    }

    impl L4Stage for CountingStage {
        type Ctx = ();

        fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
            L4Outcome::Forward
        }

        fn on_packet(&mut self, (): &mut Self::Ctx, _packet: &mut PacketContext, _dir: Direction) -> L4Outcome {
            self.packet_hits += 1;
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

    fn minimal_packet() -> PacketContext {
        let mut raw = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(12345, 80, 1, 65535)
            .write(&mut raw, b"test")
            .expect("fixture packet");
        PacketContext::from_raw(raw, Arc::from("test0")).expect("fixture packet")
    }

    #[test]
    fn counting_stage_mutates_through_hook() {
        let mut st = CountingStage::new();
        let mut ctx = ();
        let mut pkt = minimal_packet();
        assert_eq!(st.packet_hits, 0);
        let _ = st.on_packet(&mut ctx, &mut pkt, Direction::Original);
        assert_eq!(st.packet_hits, 1);
    }
}
