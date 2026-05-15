use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::AppProto;

use super::stage::{CloseReason, L4Outcome, L4Stage};

#[derive(Debug, Default)]
pub struct NoopTcpStage;

#[derive(Debug, Default)]
pub struct NoopUdpStage;

#[derive(Debug, Default)]
pub struct NoopIcmpStage;

macro_rules! impl_noop {
    ($ty:ty, $proto:expr) => {
        impl L4Stage for $ty {
            type Ctx = ();

            fn protocol(&self) -> AppProto {
                $proto
            }

            fn on_session_open(&mut self, (): &mut Self::Ctx) -> L4Outcome {
                L4Outcome::Continue
            }

            fn on_bytes(
                &mut self,
                (): &mut Self::Ctx,
                packet_id: PacketId,
                _dir: Direction,
                _tcp_payload_start_seq: u32,
                _payload: &[u8],
            ) -> L4Outcome {
                L4Outcome::Forward(vec![packet_id])
            }

            fn on_session_close(&mut self, (): &mut Self::Ctx, _reason: CloseReason) {}
        }
    };
}

impl_noop!(NoopTcpStage, AppProto::Unknown);
impl_noop!(NoopUdpStage, AppProto::Unknown);
impl_noop!(NoopIcmpStage, AppProto::Unknown);
