use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::http::HttpL4Stage;
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage};
use crate::tls::l4_inspection::TlsL4InspectionService;

pub struct TlsHttpL4Stage {
    tls: TlsL4InspectionService,
    http: HttpL4Stage,
}

impl TlsHttpL4Stage {
    pub fn new(tls: TlsL4InspectionService) -> Self {
        Self {
            tls,
            http: HttpL4Stage::new(),
        }
    }

    #[cfg(test)]
    pub fn new_with_http(tls: TlsL4InspectionService, http: HttpL4Stage) -> Self {
        Self { tls, http }
    }

    pub fn http(&self) -> &HttpL4Stage {
        &self.http
    }
}

#[tonic::async_trait]
impl L4Stage for TlsHttpL4Stage {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Tls
    }

    async fn on_session_open(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        ctx.set_application_protocol(AppProto::Tls);
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
        self.tls
            .on_encrypted_bytes(ctx, packet_id, dir, tcp_payload_start_seq, payload, &mut self.http)
            .await
    }

    async fn drain(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        self.tls.drain(ctx, &mut self.http).await
    }

    async fn on_session_close(&mut self, ctx: &mut SessionContext, reason: CloseReason) {
        self.tls.on_session_close(ctx);
        self.http.on_session_close(ctx, reason).await;
    }
}
