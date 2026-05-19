use tonic::async_trait;

use crate::dpi::DpiContext;
use crate::tls::inspection_relay::{Direction, SessionMeta};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionDisposition {
    Forward,
    Drop,
}

pub struct InspectionDecision {
    pub disposition: InspectionDisposition,
    pub ctx: DpiContext,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait DecryptedTrafficInspector: Send + Sync {
    async fn inspect(
        &self,
        payload: &[u8],
        seed_ctx: &DpiContext,
        direction: Direction,
        meta: &SessionMeta,
    ) -> InspectionDecision;

    fn close_session(&self, _meta: &SessionMeta) {}
}

pub struct NoopDecryptedInspector;

#[async_trait]
impl DecryptedTrafficInspector for NoopDecryptedInspector {
    async fn inspect(
        &self,
        payload: &[u8],
        seed_ctx: &DpiContext,
        _direction: Direction,
        _meta: &SessionMeta,
    ) -> InspectionDecision {
        InspectionDecision {
            disposition: InspectionDisposition::Forward,
            ctx: seed_ctx.clone(),
            payload: payload.to_vec(),
        }
    }
}
