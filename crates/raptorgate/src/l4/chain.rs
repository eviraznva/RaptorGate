use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketContext;

use super::stage::{CloseReason, L4Outcome, L4Stage};

pub struct L4Chain<A, B> {
    pub head: A,
    pub tail: B,
}

impl<A, B> L4Chain<A, B> {
    pub fn new(head: A, tail: B) -> Self {
        Self { head, tail }
    }

    fn combine_packet_outcome(head_out: L4Outcome, tail: &mut B, ctx: &mut A::Ctx, packet: &mut PacketContext, dir: Direction) -> L4Outcome
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        match head_out {
            L4Outcome::Drop | L4Outcome::BufferPacket | L4Outcome::TerminateSession => head_out,
            L4Outcome::Forward | L4Outcome::ForwardBuffered => tail.on_packet(ctx, packet, dir),
        }
    }

    fn combine_bytes_outcome(
        head_out: L4Outcome,
        tail: &mut B,
        ctx: &mut A::Ctx,
        packet: &mut PacketContext,
        dir: Direction,
        payload: &[u8],
    ) -> L4Outcome
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        match head_out {
            L4Outcome::Drop | L4Outcome::BufferPacket | L4Outcome::TerminateSession => head_out,
            L4Outcome::Forward | L4Outcome::ForwardBuffered => tail.on_bytes(ctx, packet, dir, payload),
        }
    }

    fn combine_open_outcome(head_out: L4Outcome, tail: &mut B, ctx: &mut A::Ctx) -> L4Outcome
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        match head_out {
            L4Outcome::Drop | L4Outcome::BufferPacket | L4Outcome::TerminateSession => head_out,
            L4Outcome::Forward | L4Outcome::ForwardBuffered => tail.on_session_open(ctx),
        }
    }

    fn combine_close_outcome(head_out: L4Outcome, tail: &mut B, ctx: &mut A::Ctx, reason: CloseReason) -> L4Outcome
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        match head_out {
            L4Outcome::Drop | L4Outcome::BufferPacket | L4Outcome::TerminateSession => head_out,
            L4Outcome::Forward | L4Outcome::ForwardBuffered => tail.on_session_close(ctx, reason),
        }
    }
}

impl<A, B> L4Stage for L4Chain<A, B>
where
    A: L4Stage,
    B: L4Stage<Ctx = A::Ctx>,
{
    type Ctx = A::Ctx;

    fn on_session_open(&mut self, ctx: &mut Self::Ctx) -> L4Outcome {
        let head_out = self.head.on_session_open(ctx);
        Self::combine_open_outcome(head_out, &mut self.tail, ctx)
    }

    fn on_packet(&mut self, ctx: &mut Self::Ctx, packet: &mut PacketContext, dir: Direction) -> L4Outcome {
        let head_out = self.head.on_packet(ctx, packet, dir);
        Self::combine_packet_outcome(head_out, &mut self.tail, ctx, packet, dir)
    }

    fn on_bytes(
        &mut self,
        ctx: &mut Self::Ctx,
        packet: &mut PacketContext,
        dir: Direction,
        payload: &[u8],
    ) -> L4Outcome {
        let head_out = self.head.on_bytes(ctx, packet, dir, payload);
        Self::combine_bytes_outcome(head_out, &mut self.tail, ctx, packet, dir, payload)
    }

    fn on_session_close(&mut self, ctx: &mut Self::Ctx, reason: CloseReason) -> L4Outcome {
        let head_out = self.head.on_session_close(ctx, reason);
        Self::combine_close_outcome(head_out, &mut self.tail, ctx, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::sync::Arc;

    struct ForwardHead {
        calls: u32,
    }

    impl L4Stage for ForwardHead {
        type Ctx = ();

        fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
            L4Outcome::Forward
        }

        fn on_packet(&mut self, (): &mut Self::Ctx, _packet: &mut PacketContext, _dir: Direction) -> L4Outcome {
            self.calls += 1;
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

    struct ObservingTail {
        packet_seen: u32,
    }

    impl L4Stage for ObservingTail {
        type Ctx = ();

        fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
            L4Outcome::Forward
        }

        fn on_packet(&mut self, (): &mut Self::Ctx, _packet: &mut PacketContext, _dir: Direction) -> L4Outcome {
            self.packet_seen += 1;
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

    struct DropHead;

    impl L4Stage for DropHead {
        type Ctx = ();

        fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
            L4Outcome::Forward
        }

        fn on_packet(&mut self, (): &mut Self::Ctx, _packet: &mut PacketContext, _dir: Direction) -> L4Outcome {
            L4Outcome::Drop
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
    fn forward_reaches_tail() {
        let mut chain = L4Chain::new(ForwardHead { calls: 0 }, ObservingTail { packet_seen: 0 });
        let mut ctx = ();
        let mut pkt = minimal_packet();
        let out = chain.on_packet(&mut ctx, &mut pkt, Direction::Original);
        assert_eq!(out, L4Outcome::Forward);
        assert_eq!(chain.head.calls, 1);
        assert_eq!(chain.tail.packet_seen, 1);
    }

    #[test]
    fn drop_stops_before_tail() {
        let mut chain = L4Chain::new(DropHead, ObservingTail { packet_seen: 0 });
        let mut ctx = ();
        let mut pkt = minimal_packet();
        let out = chain.on_packet(&mut ctx, &mut pkt, Direction::Original);
        assert_eq!(out, L4Outcome::Drop);
        assert_eq!(chain.tail.packet_seen, 0);
    }
}
