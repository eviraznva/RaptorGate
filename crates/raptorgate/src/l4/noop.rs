use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;

use super::stage::{CloseReason, L4Outcome, L4Stage};

#[derive(Debug, Default)]
pub struct NoopTcpStage;

#[derive(Debug, Default)]
pub struct NoopUdpStage;

#[derive(Debug, Default)]
pub struct NoopIcmpStage;

macro_rules! impl_noop {
    ($ty:ty, $proto:expr) => {
        #[tonic::async_trait]
        impl L4Stage for $ty {
            type Ctx = SessionContext;

            fn protocol(&self) -> AppProto {
                $proto
            }

            async fn on_session_open(&mut self, _ctx: &mut SessionContext) -> L4Outcome {
                L4Outcome::Continue
            }

            async fn on_bytes(
                &mut self,
                _ctx: &mut SessionContext,
                packet_id: PacketId,
                _dir: Direction,
                _tcp_payload_start_seq: u32,
                _payload: &[u8],
            ) -> L4Outcome {
                tracing::trace!(stage=stringify!($ty), "NoopStage received bytes for packet {packet_id:?}");
                L4Outcome::Forward(vec![packet_id])
            }

            async fn on_session_close(&mut self, _ctx: &mut SessionContext, _reason: CloseReason) {}
        }
    };
}

impl_noop!(NoopTcpStage, AppProto::Unknown);
impl_noop!(NoopUdpStage, AppProto::Unknown);
impl_noop!(NoopIcmpStage, AppProto::Unknown);
