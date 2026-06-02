use ngfw::daemon::ProcessOutput;
use ngfw::l4::release::PacketDispositionOutcome;
use ngfw::pipeline::{ExecutionAction, StageOutcome};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineOutcome {
    Forwarded,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    Pipeline(PipelineOutcome),
    Disposition(PacketDispositionOutcome),
}

#[derive(Debug, Error)]
pub enum PipelineMismatch {
    #[error("expected pipeline {expected:?} got {actual:?} (emitted={emitted}, stage={stage:?})")]
    Mismatch {
        expected: PipelineOutcome,
        actual: PipelineOutcome,
        emitted: usize,
        stage: Option<StageOutcome>,
    },
}

pub fn reduce_legacy_daemon_process_output(output: &ProcessOutput) -> PipelineOutcome {
    if output
        .emitted
        .iter()
        .any(|e| matches!(e.action, ExecutionAction::Forward))
    {
        return PipelineOutcome::Forwarded;
    }
    if matches!(&output.stage_outcome, Some(StageOutcome::Continue)) {
        return PipelineOutcome::Forwarded;
    }
    if matches!(&output.stage_outcome, Some(StageOutcome::ReleaseBatch(_))) {
        return PipelineOutcome::Forwarded;
    }
    PipelineOutcome::Rejected
}

pub fn reduce_daemon_v2_process_output(output: &ProcessOutput) -> PipelineOutcome {
    if output
        .emitted
        .iter()
        .any(|e| matches!(e.action, ExecutionAction::Forward))
    {
        return PipelineOutcome::Forwarded;
    }
    if matches!(&output.stage_outcome, Some(StageOutcome::Continue)) {
        return PipelineOutcome::Forwarded;
    }
    if matches!(&output.stage_outcome, Some(StageOutcome::ReleaseBatch(_))) {
        return PipelineOutcome::Forwarded;
    }
    if matches!(&output.stage_outcome, Some(StageOutcome::Halt))
        && output.emitted.len() == 1
        && matches!(
            output.emitted.first(),
            Some(item) if matches!(item.action, ExecutionAction::Drop)
        )
    {
        return PipelineOutcome::Forwarded;
    }
    PipelineOutcome::Rejected
}

pub fn check_v2_pipeline(
    output: &ProcessOutput,
    expected: PipelineOutcome,
) -> Result<(), PipelineMismatch> {
    let actual = reduce_daemon_v2_process_output(output);
    if actual == expected {
        Ok(())
    } else {
        Err(PipelineMismatch::Mismatch {
            expected,
            actual,
            emitted: output.emitted.len(),
            stage: output.stage_outcome.clone(),
        })
    }
}

pub fn check_legacy_pipeline(
    output: &ProcessOutput,
    expected: PipelineOutcome,
) -> Result<(), PipelineMismatch> {
    let actual = reduce_legacy_daemon_process_output(output);
    if actual == expected {
        Ok(())
    } else {
        Err(PipelineMismatch::Mismatch {
            expected,
            actual,
            emitted: output.emitted.len(),
            stage: output.stage_outcome.clone(),
        })
    }
}

pub fn count_tcp_rst_in_output(output: &ProcessOutput) -> usize {
    output
        .emitted
        .iter()
        .filter(|item| {
            let raw = item.packet.borrow_raw();
            if let Ok(slice) = etherparse::SlicedPacket::from_ethernet(raw)
                && let Some(etherparse::TransportSlice::Tcp(tcp)) = slice.transport
            {
                return !tcp.syn() && !tcp.fin() && tcp.rst();
            }
            false
        })
        .count()
}
