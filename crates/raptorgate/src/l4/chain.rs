use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::AppProto;

use super::stage::{CloseReason, L4Outcome, L4Stage};

pub struct L4Chain<A, B> {
    pub head: A,
    pub tail: B,
}

impl<A, B> L4Chain<A, B> {
    pub fn new(head: A, tail: B) -> Self {
        Self { head, tail }
    }

    fn stage_applies(stage_proto: AppProto, session_proto: Option<AppProto>) -> bool {
        matches!(stage_proto, AppProto::Any)
            || session_proto.is_none()
            || session_proto == Some(stage_proto)
    }

    fn combine_open_outcome(
        head_out: L4Outcome,
        tail: &mut B,
        ctx: &mut A::Ctx,
        session_proto: Option<AppProto>,
    ) -> L4Outcome
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        match head_out {
            L4Outcome::Continue => {
                if Self::stage_applies(tail.protocol(), session_proto) {
                    tail.on_session_open(ctx)
                } else {
                    L4Outcome::Continue
                }
            }
            L4Outcome::Forward(_) | L4Outcome::Terminate { .. } => head_out,
        }
    }

    fn combine_bytes_outcome(
        head_out: L4Outcome,
        tail: &mut B,
        ctx: &mut A::Ctx,
        packet_id: PacketId,
        dir: Direction,
        payload: &[u8],
        session_proto: Option<AppProto>,
    ) -> L4Outcome
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        match head_out {
            L4Outcome::Continue => {
                if Self::stage_applies(tail.protocol(), session_proto) {
                    tail.on_bytes(ctx, packet_id, dir, payload)
                } else {
                    L4Outcome::Continue
                }
            }
            L4Outcome::Forward(_) | L4Outcome::Terminate { .. } => head_out,
        }
    }

    fn run_close_tail(tail: &mut B, ctx: &mut <A as L4Stage>::Ctx, reason: CloseReason, session_proto: Option<AppProto>)
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        if Self::stage_applies(tail.protocol(), session_proto) {
            tail.on_session_close(ctx, reason);
        }
    }

    pub fn on_session_open(&mut self, ctx: &mut A::Ctx, session_proto: Option<AppProto>) -> L4Outcome
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        if !Self::stage_applies(self.head.protocol(), session_proto) {
            return L4Outcome::Continue;
        }
        let head_out = self.head.on_session_open(ctx);
        Self::combine_open_outcome(head_out, &mut self.tail, ctx, session_proto)
    }

    pub fn on_bytes(
        &mut self,
        ctx: &mut A::Ctx,
        packet_id: PacketId,
        dir: Direction,
        payload: &[u8],
        session_proto: Option<AppProto>,
    ) -> L4Outcome
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        if !Self::stage_applies(self.head.protocol(), session_proto) {
            return L4Outcome::Continue;
        }
        let head_out = self.head.on_bytes(ctx, packet_id, dir, payload);
        Self::combine_bytes_outcome(head_out, &mut self.tail, ctx, packet_id, dir, payload, session_proto)
    }

    pub fn on_session_close(&mut self, ctx: &mut A::Ctx, reason: CloseReason, session_proto: Option<AppProto>)
    where
        A: L4Stage,
        B: L4Stage<Ctx = A::Ctx>,
    {
        if Self::stage_applies(self.head.protocol(), session_proto) {
            self.head.on_session_close(ctx, reason);
        }
        Self::run_close_tail(&mut self.tail, ctx, reason, session_proto);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::AppProto;

    struct ForwardHead;

    impl L4Stage for ForwardHead {
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
            L4Outcome::Forward(vec![packet_id])
        }

        fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) {}
    }

    struct ObservingTail {
        byte_seen: bool,
    }

    impl L4Stage for ObservingTail {
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
            _packet_id: PacketId,
            _dir: Direction,
            _payload: &[u8],
        ) -> L4Outcome {
            self.byte_seen = true;
            L4Outcome::Continue
        }

        fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) {}
    }

    struct TerminateHead;

    impl L4Stage for TerminateHead {
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
            _packet_id: PacketId,
            _dir: Direction,
            _payload: &[u8],
        ) -> L4Outcome {
            L4Outcome::Terminate {
                reason: super::super::stage::TerminateReason::StageRequested,
                reset: false,
            }
        }

        fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) {}
    }

    #[test]
    fn forward_short_circuits_tail() {
        let mut chain = L4Chain::new(ForwardHead, ObservingTail { byte_seen: false });
        let mut ctx = ();
        let id = PacketId::next();
        let out = chain.on_bytes(&mut ctx, id, Direction::Original, b"test", None);
        assert!(matches!(out, L4Outcome::Forward(ids) if ids == vec![id]));
        assert!(!chain.tail.byte_seen);
    }

    #[test]
    fn terminate_stops_before_tail() {
        let mut chain = L4Chain::new(TerminateHead, ObservingTail { byte_seen: false });
        let mut ctx = ();
        let out = chain.on_bytes(&mut ctx, PacketId::next(), Direction::Original, b"x", None);
        assert!(matches!(out, L4Outcome::Terminate { .. }));
        assert!(!chain.tail.byte_seen);
    }
}
