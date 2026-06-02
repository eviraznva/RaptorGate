use std::sync::Arc;

use crate::data_plane::packet_context::PacketId;
use crate::conntrack::tuple::Direction;
use crate::dpi::smtp_l4_session::SmtpSession;
use crate::dpi::smtp_policy_retriever::SmtpPolicyRetriever;
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage};
use crate::zones::resolver::ZoneResolver;

pub struct SmtpL4Stage<ZR> {
    session: SmtpSession<ZR>,
}

impl<ZR: ZoneResolver> SmtpL4Stage<ZR> {
    pub fn new(policy_retriever: Arc<SmtpPolicyRetriever<ZR>>) -> Self {
        Self {
            session: SmtpSession::new(policy_retriever),
        }
    }
}

impl<ZR: ZoneResolver> L4Stage for SmtpL4Stage<ZR> {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Smtp
    }

    fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
        L4Outcome::Continue
    }

    fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        _tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        self.session.process_bytes(ctx, packet_id, dir, payload)
    }

    fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {
        self.session.on_session_close();
    }
}

