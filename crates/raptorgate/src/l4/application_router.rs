use std::sync::Arc;

use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::smtp_l4_stage::SmtpL4Stage;
use crate::dpi::smtp_policy_retriever::SmtpPolicyRetriever;
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::factory::{TcpPassThroughStage, TcpSessionPipeline};
use crate::l4::http::HttpL4Stage;
use crate::l4::stage::{CloseReason, L4Emit, L4Outcome, L4Stage, TerminateReason};
use crate::l4::tls::TlsHttpL4Stage;
use crate::tls::l4_inspection::{TlsL4InspectionConfig, TlsL4InspectionService};
use crate::zones::resolver::ZoneResolver;

const MAX_PENDING_BYTES: usize = 64 * 1024;

struct BufferedBytes {
    packet_id: PacketId,
    dir: Direction,
    tcp_payload_start_seq: u32,
    payload: Vec<u8>,
}

pub struct ApplicationRouterStage<ZR: ZoneResolver> {
    smtp_policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
    tls_inspection: Option<Arc<TlsL4InspectionConfig>>,
    selected: Option<Box<TcpSessionPipeline<ZR>>>,
    pending: Vec<BufferedBytes>,
    pending_bytes: usize,
}

impl<ZR: ZoneResolver> ApplicationRouterStage<ZR> {
    pub fn new(
        smtp_policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
        tls_inspection: Option<Arc<TlsL4InspectionConfig>>,
    ) -> Self {
        Self {
            smtp_policy_retriever,
            tls_inspection,
            selected: None,
            pending: Vec::new(),
            pending_bytes: 0,
        }
    }

    pub async fn on_bytes_with_app_proto(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
        app_proto: Option<AppProto>,
    ) -> L4Outcome {
        if let Some(selected) = &mut self.selected {
            return selected.on_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload).await;
        }

        if payload.is_empty() {
            return L4Outcome::Forward(vec![packet_id]);
        }

        self.pending_bytes += payload.len();
        self.pending.push(BufferedBytes {
            packet_id,
            dir,
            tcp_payload_start_seq,
            payload: payload.to_vec(),
        });

        let app_proto = app_proto.or_else(|| {
            (self.pending_bytes > MAX_PENDING_BYTES).then_some(AppProto::Unknown)
        });
        let Some(app_proto) = app_proto else {
            return L4Outcome::Continue;
        };

        let mut selected = self.pipeline_for_app_proto(app_proto);
        let open = selected.on_session_open(ctx).await;
        let mut parts = OutcomeParts::default();
        parts.push(open);
        if parts.terminate.is_some() {
            self.pending.clear();
            self.pending_bytes = 0;
            return parts.finish();
        }

        let pending = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        for item in pending {
            let out = selected
                .on_bytes(ctx, item.packet_id, item.dir, item.tcp_payload_start_seq, &item.payload)
                .await;
            parts.push(out);
            if parts.terminate.is_some() {
                return parts.finish();
            }
        }

        self.selected = Some(Box::new(selected));
        parts.finish()
    }

    fn pipeline_for_app_proto(&self, app_proto: AppProto) -> TcpSessionPipeline<ZR> {
        match app_proto {
            AppProto::Http => TcpSessionPipeline::Http(HttpL4Stage::new()),
            AppProto::Smtp => TcpSessionPipeline::Smtp(SmtpL4Stage::new(Arc::clone(&self.smtp_policy_retriever))),
            AppProto::Tls => match &self.tls_inspection {
                Some(tls_inspection) => TcpSessionPipeline::TlsHttp(TlsHttpL4Stage::new(TlsL4InspectionService::new(Arc::clone(tls_inspection)))),
                None => TcpSessionPipeline::PassThrough(TcpPassThroughStage::default()),
            },
            _ => TcpSessionPipeline::PassThrough(TcpPassThroughStage::default()),
        }
    }
}

#[derive(Default)]
struct OutcomeParts {
    forward: Vec<PacketId>,
    drop: Vec<PacketId>,
    emit: Vec<L4Emit>,
    terminate: Option<(TerminateReason, bool)>,
}

impl OutcomeParts {
    fn push(&mut self, outcome: L4Outcome) {
        match outcome {
            L4Outcome::Continue => {}
            L4Outcome::Forward(ids) => self.forward.extend(ids),
            L4Outcome::Drop(ids) => self.drop.extend(ids),
            L4Outcome::Emit(emit) => self.emit.extend(emit),
            L4Outcome::ForwardAndEmit { forward, emit } => {
                self.forward.extend(forward);
                self.emit.extend(emit);
            }
            L4Outcome::Terminate { reason, reset } => self.terminate = Some((reason, reset)),
        }
    }

    fn finish(self) -> L4Outcome {
        if let Some((reason, reset)) = self.terminate {
            return L4Outcome::Terminate { reason, reset };
        }
        if !self.drop.is_empty() {
            return L4Outcome::Drop(self.drop);
        }
        if !self.forward.is_empty() && !self.emit.is_empty() {
            return L4Outcome::ForwardAndEmit {
                forward: self.forward,
                emit: self.emit,
            };
        }
        if !self.forward.is_empty() {
            return L4Outcome::Forward(self.forward);
        }
        if !self.emit.is_empty() {
            return L4Outcome::Emit(self.emit);
        }
        L4Outcome::Continue
    }
}

#[tonic::async_trait]
impl<ZR: ZoneResolver + Send + Sync> L4Stage for ApplicationRouterStage<ZR> {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        self.selected
            .as_ref()
            .map(|selected| selected.protocol())
            .unwrap_or(AppProto::Unknown)
    }

    async fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
        L4Outcome::Continue
    }

    async fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        self.on_bytes_with_app_proto(ctx, packet_id, dir, tcp_payload_start_seq, payload, None).await
    }

    async fn drain(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        match &mut self.selected {
            Some(selected) => selected.drain(ctx).await,
            None => L4Outcome::Continue,
        }
    }

    async fn on_session_close(&mut self, ctx: &mut SessionContext, reason: CloseReason) {
        if let Some(selected) = &mut self.selected {
            selected.on_session_close(ctx, reason).await;
        }
        self.pending.clear();
        self.pending_bytes = 0;
    }
}
