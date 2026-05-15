use std::collections::VecDeque;
use std::sync::Arc;

use dashmap::DashMap;

use crate::conntrack::tcp_identity::{EndpointIdentifier, TcpIdentifier};
use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::smtp::{
    BufferingDisposition, PacketAction, SmtpProtocolMachine, TerminatedSmtpSession, UnitStatus,
};
use crate::dpi::smtp_policy_retriever::SmtpPolicyRetriever;
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage, TerminateReason};
use crate::zones::resolver::ZoneResolver;

pub struct SmtpL4Stage<ZR> {
    machine: SmtpProtocolMachine,
    policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
    packet_ids: VecDeque<PacketId>,
    terminated_sessions: Arc<DashMap<TcpIdentifier, TerminatedSmtpSession>>,
}

impl<ZR> SmtpL4Stage<ZR> {
    pub fn new(policy_retriever: Arc<SmtpPolicyRetriever<ZR>>) -> Self {
        Self {
            machine: SmtpProtocolMachine::default(),
            policy_retriever,
            packet_ids: VecDeque::new(),
            terminated_sessions: Arc::new(DashMap::new()),
        }
    }

    pub(crate) fn terminated_sessions(&self) -> Arc<DashMap<TcpIdentifier, TerminatedSmtpSession>> {
        Arc::clone(&self.terminated_sessions)
    }

    fn flow_key(ctx: &SessionContext) -> TcpIdentifier {
        let e = ctx.entry().original;
        TcpIdentifier::new(
            EndpointIdentifier {
                ip: e.src_ip,
                port: e.src_port.into(),
            },
            EndpointIdentifier {
                ip: e.dst_ip,
                port: e.dst_port.into(),
            },
        )
    }

    fn endpoints(ctx: &SessionContext, dir: Direction) -> (EndpointIdentifier, EndpointIdentifier) {
        let t = match dir {
            Direction::Original => ctx.entry().original,
            Direction::Reply => ctx.entry().reply(),
        };
        (
            EndpointIdentifier {
                ip: t.src_ip,
                port: t.src_port.into(),
            },
            EndpointIdentifier {
                ip: t.dst_ip,
                port: t.dst_port.into(),
            },
        )
    }

    fn disposition_to_outcome(&mut self, packet_id: PacketId, d: BufferingDisposition) -> L4Outcome {
        match d.packet {
            PacketAction::Pass => L4Outcome::Forward(vec![packet_id]),
            PacketAction::QueueAndHalt => {
                self.packet_ids.push_back(packet_id);
                if d.unit == UnitStatus::Complete {
                    L4Outcome::Forward(self.packet_ids.drain(..).collect())
                } else {
                    L4Outcome::Continue
                }
            }
            PacketAction::Drop => {
                self.packet_ids.clear();
                L4Outcome::Terminate {
                    reason: TerminateReason::SmtpPolicyDenied,
                    reset: true,
                }
            }
        }
    }
}

impl<ZR: ZoneResolver> L4Stage for SmtpL4Stage<ZR> {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Smtp
    }

    fn on_session_open(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        ctx.set_application_protocol(AppProto::Smtp);
        L4Outcome::Continue
    }

    fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        let flow = Self::flow_key(ctx);
        let (src, dst) = Self::endpoints(ctx, dir);
        let (disp, _remove, _rsts) = self.machine.feed_tcp(
            None,
            Some(&mut self.packet_ids),
            &self.policy_retriever,
            &self.terminated_sessions,
            &flow,
            src,
            dst,
            tcp_payload_start_seq,
            payload,
        );
        self.disposition_to_outcome(packet_id, disp)
    }

    fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {}
}
