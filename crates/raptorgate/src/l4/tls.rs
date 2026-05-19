use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::http::HttpL4Stage;
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage, TerminateReason};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4PlaintextChunk {
    pub dir: Direction,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsInspectionOutcome {
    NeedMore,
    Plaintext(Vec<L4PlaintextChunk>),
    Drop { reset: bool },
}

pub trait TlsInspectionService: Send {
    fn inspect(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> TlsInspectionOutcome;
}

pub struct TlsHttpL4Stage<S> {
    tls: S,
    http: HttpL4Stage,
}

impl<S> TlsHttpL4Stage<S> {
    pub fn new(tls: S, http: HttpL4Stage) -> Self {
        Self { tls, http }
    }

    pub fn http(&self) -> &HttpL4Stage {
        &self.http
    }
}

impl<S> L4Stage for TlsHttpL4Stage<S>
where
    S: TlsInspectionService,
{
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Tls
    }

    fn on_session_open(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        ctx.set_application_protocol(AppProto::Tls);
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
        match self.tls.inspect(ctx, packet_id, dir, tcp_payload_start_seq, payload) {
            TlsInspectionOutcome::NeedMore => L4Outcome::Continue,
            TlsInspectionOutcome::Plaintext(chunks) => {
                for chunk in chunks {
                    self.http.inspect_plaintext(ctx, &chunk.payload);
                }
                L4Outcome::Forward(vec![packet_id])
            }
            TlsInspectionOutcome::Drop { reset } => L4Outcome::Terminate {
                reason: TerminateReason::StageRequested,
                reset,
            },
        }
    }

    fn on_session_close(&mut self, ctx: &mut SessionContext, reason: CloseReason) {
        self.http.on_session_close(ctx, reason);
    }
}
