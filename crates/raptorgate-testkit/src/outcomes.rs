use ngfw::daemon::ProcessOutput;
use ngfw::pipeline::{ExecutionAction, StageOutcome};
use thiserror::Error;

pub trait ProcessOutputAssertExt {
    fn assert_outcome(&self, expected: PipelineOutcome) -> Result<(), OutcomeMismatch>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineOutcome {
    Forward,
    Drop,
    BufferedNoEmission,
    ReleasedBatch { count: Option<usize> },
    TcpReset { count: Option<usize> },
    NoEmission,
}

#[derive(Debug, Error)]
pub enum OutcomeMismatch {
    #[error("expected {expected:?} got emitted={emitted:?} stage_outcome={stage_outcome:?}")]
    Mismatch {
        expected: PipelineOutcome,
        emitted: usize,
        stage_outcome: Option<StageOutcome>,
    },
}

fn count_tcp_rst(emitted: &[ngfw::pipeline::ExecutionItem]) -> usize {
    emitted
        .iter()
        .filter(|item| {
            let raw = item.packet.borrow_raw();
            if let Ok(slice) = etherparse::SlicedPacket::from_ethernet(raw)
                && let Some(etherparse::TransportSlice::Tcp(tcp)) = slice.transport {
                    return !tcp.syn()
                        && !tcp.fin()
                        && tcp.rst();
                }
            false
        })
        .count()
}

impl ProcessOutputAssertExt for ProcessOutput {
    fn assert_outcome(&self, expected: PipelineOutcome) -> Result<(), OutcomeMismatch> {
        let n = self.emitted.len();
        let forwards = self
            .emitted
            .iter()
            .filter(|e| matches!(e.action, ExecutionAction::Forward))
            .count();
        let drops = self
            .emitted
            .iter()
            .filter(|e| matches!(e.action, ExecutionAction::Drop))
            .count();
        let stage = self.stage_outcome.clone();

        let ok = match &expected {
            PipelineOutcome::Forward => forwards == 1 && drops == 0,
            PipelineOutcome::Drop => drops >= 1 && forwards == 0,
            PipelineOutcome::BufferedNoEmission => {
                n == 0 && matches!(stage, Some(StageOutcome::Halt | StageOutcome::ReleaseBatch(_)))
            }
            PipelineOutcome::ReleasedBatch { count } => {
                let c = forwards;
                match count {
                    Some(k) => *k == c && drops == 0,
                    None => c > 0 && drops == 0,
                }
            }
            PipelineOutcome::TcpReset { count } => {
                let r = count_tcp_rst(&self.emitted);
                match count {
                    Some(k) => *k == r,
                    None => r > 0,
                }
            }
            PipelineOutcome::NoEmission => n == 0,
        };

        if ok {
            Ok(())
        } else {
            Err(OutcomeMismatch::Mismatch {
                expected,
                emitted: n,
                stage_outcome: stage,
            })
        }
    }
}
