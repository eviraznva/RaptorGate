use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::parsers::http;
use crate::dpi::{AppProto, DpiContext};
use crate::l4::context::SessionContext;
use crate::l4::stage::{CloseReason, L4Outcome, L4Stage};

const DEFAULT_MAX_BUFFER: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct HttpL4Stage {
    dpi: DpiContext,
    buffer: Vec<u8>,
    max_buffer: usize,
}

impl HttpL4Stage {
    pub fn new() -> Self {
        Self {
            dpi: DpiContext::default(),
            buffer: Vec::new(),
            max_buffer: DEFAULT_MAX_BUFFER,
        }
    }

    pub fn dpi_context(&self) -> &DpiContext {
        &self.dpi
    }

    pub fn inspect_plaintext(&mut self, ctx: &mut SessionContext, payload: &[u8]) {
        self.inspect_payload(ctx, payload);
    }

    fn inspect_payload(&mut self, ctx: &mut SessionContext, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        self.buffer.extend_from_slice(payload);
        if self.buffer.len() > self.max_buffer {
            let overflow = self.buffer.len() - self.max_buffer;
            self.buffer.drain(..overflow);
        }
        if let Some(parsed) = http::parse_http(&self.buffer) {
            http::merge_http_dpi_context(&mut self.dpi, &parsed);
            ctx.set_application_protocol(AppProto::Http);
        }
    }
}

impl Default for HttpL4Stage {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl L4Stage for HttpL4Stage {
    type Ctx = SessionContext;

    fn protocol(&self) -> AppProto {
        AppProto::Http
    }

    async fn on_session_open(&mut self, ctx: &mut SessionContext) -> L4Outcome {
        ctx.set_application_protocol(AppProto::Http);
        L4Outcome::Continue
    }

    async fn on_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        _dir: Direction,
        _tcp_payload_start_seq: u32,
        payload: &[u8],
    ) -> L4Outcome {
        self.inspect_payload(ctx, payload);
        L4Outcome::Forward(vec![packet_id])
    }

    async fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::entry::ConntrackEntry;
    use crate::conntrack::proto::tcp::TcpProtoState;
    use crate::conntrack::proto::ProtoState;
    use crate::conntrack::tuple::{FlowTuple, Protocol};
    use crate::zones::resolver::ZoneResolver;
    use crate::zones::{DirectionalZonePairs, ResolvedZonePair, ZonePairId};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    struct StubZoneResolver;

    impl ZoneResolver for StubZoneResolver {
        fn resolve(&self, _src_interface_name: &str, _dst_ip: IpAddr) -> Option<ResolvedZonePair> {
            Some(ResolvedZonePair {
                id: ZonePairId::from(uuid::Uuid::nil()),
                default_policy: crate::zones::DefaultPolicy::Allow,
            })
        }

        fn resolve_bidirectional(&self, _src_ip: IpAddr, _dst_ip: IpAddr) -> DirectionalZonePairs {
            let pair = ResolvedZonePair {
                id: ZonePairId::from(uuid::Uuid::nil()),
                default_policy: crate::zones::DefaultPolicy::Allow,
            };
            DirectionalZonePairs {
                forward: Some(pair.clone()),
                reverse: Some(pair),
            }
        }
    }

    fn sample_tcp_context() -> SessionContext {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            Protocol::Tcp,
        );
        let entry = Arc::new(ConntrackEntry::new(
            7,
            tuple,
            ProtoState::Tcp(TcpProtoState::default()),
            Duration::from_secs(60),
            0,
        ));
        SessionContext::open(entry, &StubZoneResolver)
    }

    #[tokio::test]
    async fn http_stage_accepts_decrypted_plaintext() {
        let mut stage = HttpL4Stage::new();
        let mut ctx = sample_tcp_context();

        stage.inspect_plaintext(&mut ctx, b"GET / HTTP/1.1\r\nHost: tls.example\r\n\r\n");

        assert_eq!(ctx.application_protocol(), Some(AppProto::Http));
        assert_eq!(stage.dpi_context().http_host.as_deref(), Some("tls.example"));
    }
}
