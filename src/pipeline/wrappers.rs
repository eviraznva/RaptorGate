use std::sync::Arc;

use crate::{
    data_plane::{
        packet_context::PacketContext,
        policy_store::PolicyStore,
        tcp_session_tracker::TcpSessionTracker,
    },
    pipeline::{Stage, StageOutcome},
    rule_tree::{ArrivalInfo, Verdict},
};

#[derive(Clone)]
pub struct PolicyEvalStage {
    pub policies: Arc<PolicyStore>,
}

impl Stage for PolicyEvalStage {
    async fn process(&self, ctx: &mut PacketContext) -> StageOutcome {
        let compiled = self.policies.load();
        let arrival = ArrivalInfo::from_time(ctx.borrow_arrival_time());
        let verdict = compiled.evaluator().evaluate(ctx.borrow_sliced_packet(), &arrival);

        match verdict {
            Verdict::Allow => StageOutcome::Continue,
            Verdict::Drop => StageOutcome::Halt,
            Verdict::AllowWarn(msg) => {
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Continue
            }
            Verdict::DropWarn(msg) => {
                ctx.with_warnings_mut(|w| w.push(msg));
                StageOutcome::Halt
            }
        }
    }
}

#[derive(Clone)]
pub struct TcpClassificationStage {
    pub tracker: Arc<TcpSessionTracker>,
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
