use crate::{data_plane::{packet_context::PacketContext, tcp_session_tracker::TcpSessionTracker}, pipeline::{Stage, StageOutcome}};

struct TcpClassificationStage {
    tracker: &'static TcpSessionTracker,
}

impl Stage for TcpClassificationStage {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        match self.tracker.process_packet(ctx.borrow_sliced_packet()) {
            Ok(_) => StageOutcome::Continue,
            Err(e) => {
                tracing::error!(error = %e, "TCP session tracking error");
                StageOutcome::Halt
            },
        }
    }
}
