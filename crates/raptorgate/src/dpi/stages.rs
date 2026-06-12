use std::sync::Arc;

use crate::data_plane::packet_context::PacketId;
use crate::conntrack::tuple::Direction;
use crate::dpi::smtp::smtp_l4_session::SmtpSession;
use crate::policy::retriever::PolicyRetriever;
use crate::dpi::smtp::{BufferingDisposition, PacketAction};
use crate::dpi::ssh::SshSession;
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage, TerminateReason};
use crate::zones::resolver::ZoneResolver;

pub struct SmtpL4Stage<ZR> {
    session: SmtpSession<ZR>,
}

impl<ZR: ZoneResolver> SmtpL4Stage<ZR> {
    pub fn new(policy_retriever: Arc<PolicyRetriever<ZR>>) -> Self {
        Self {
            session: SmtpSession::new(policy_retriever),
        }
    }
}

#[tonic::async_trait]
impl<ZR: ZoneResolver + Send + Sync> L4Stage for SmtpL4Stage<ZR> {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Smtp
    }

    async fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
        L4Outcome::Continue
    }

    async fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        _tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        self.session.process_bytes(ctx, packet_id, dir, payload)
    }

    async fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {
        self.session.on_session_close();
    }
}

pub struct SshL4Stage<ZR: ZoneResolver> {
    session: SshSession<ZR>,
}

impl<ZR: ZoneResolver> SshL4Stage<ZR> {
    pub fn new(policy_retriever: Arc<PolicyRetriever<ZR>>) -> Self {
        Self {
            session: SshSession::new(policy_retriever),
        }
    }
}

#[tonic::async_trait]
impl<ZR: ZoneResolver + Send + Sync> L4Stage for SshL4Stage<ZR> {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Ssh
    }

    async fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
        L4Outcome::Continue
    }

    async fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        _tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        match self.session.process_bytes(ctx, packet_id, dir, payload) {
            BufferingDisposition { packet: PacketAction::Drop, .. } => L4Outcome::Terminate {
                reason: TerminateReason::StageRequested,
                reset: true,
            },
            _ => L4Outcome::Forward(vec![packet_id]),
        }
    }

    async fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {}
}
