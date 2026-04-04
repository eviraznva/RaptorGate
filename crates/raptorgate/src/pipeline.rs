pub mod wrappers;

use crate::data_plane::packet_context::PacketContext;

pub trait Stage: Send + Sync {
    fn is_applicable(&self, ctx: &PacketContext) -> bool { true }
    fn process(&self, ctx: &mut PacketContext) -> impl std::future::Future<Output = StageOutcome> + Send;
}

pub enum StageOutcome { Continue, Halt }

#[derive(Clone)]
pub struct Chain<A: Stage + Clone, B: Stage + Clone> { pub head: A, pub tail: B }
impl<A, B> Stage for Chain<A, B> where A: Stage + Clone, B: Stage + Clone {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let outcome = if self.head.is_applicable(ctx) {
            self.head.process(ctx).await
        } else {
            StageOutcome::Continue
        };
        match outcome {
            StageOutcome::Continue => self.tail.process(ctx).await,
            StageOutcome::Halt     => StageOutcome::Halt,
        }
    }
}
