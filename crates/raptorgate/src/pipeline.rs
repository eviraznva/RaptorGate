pub mod wrappers;

use std::collections::VecDeque;

use tokio::sync::mpsc;

use crate::data_plane::packet_context::{CaptureDirection, PacketContext};

#[derive(Debug)]
pub enum ExecutionAction { Forward, Drop }

#[derive(Debug)]
pub struct ExecutionItem {
    pub packet: PacketContext,
    pub action: ExecutionAction,
}

pub type ExecutionSender = mpsc::UnboundedSender<ExecutionItem>;
pub type ExecutionReceiver = mpsc::UnboundedReceiver<ExecutionItem>;

pub struct ExecutionSink {
    tun: std::sync::Arc<crate::data_plane::tun_forwarder::TunForwarder>,
    metrics: std::sync::Arc<crate::metrics::MetricsCollector>,
    receiver: ExecutionReceiver,
}

impl ExecutionSink {
    pub fn new(
        tun: std::sync::Arc<crate::data_plane::tun_forwarder::TunForwarder>,
        metrics: std::sync::Arc<crate::metrics::MetricsCollector>,
        receiver: ExecutionReceiver,
    ) -> Self {
        Self { tun, metrics, receiver }
    }

    pub async fn run(mut self) {
        tracing::info!(event = "execution_sink.started", "execution sink started");
        while let Some(item) = self.receiver.recv().await {
            match item.action {
                ExecutionAction::Forward => {
                    tracing::trace!(
                        event = "execution.forward",
                        iface = %item.packet.borrow_src_interface(),
                        packet_len = item.packet.borrow_raw().len(),
                        "forwarding packet to TUN"
                    );
                    self.tun.forward(&item.packet).await;
                }
                ExecutionAction::Drop => {
                    tracing::trace!(
                        event = "execution.drop",
                        iface = %item.packet.borrow_src_interface(),
                        packet_len = item.packet.borrow_raw().len(),
                        "recording packet drop"
                    );
                    self.metrics.observe_drop();
                }
            }
        }
        tracing::info!(event = "execution_sink.stopped", "execution sink stopped");
    }
}

pub trait Stage: Send + Sync {
    fn is_applicable(&self, ctx: &PacketContext) -> bool { true }
    fn runs_on_egress(&self) -> bool { false }
    fn process(&self, ctx: &mut PacketContext, tx: &ExecutionSender) -> impl std::future::Future<Output = StageOutcome> + Send;
}

fn stage_should_run<S: Stage + ?Sized>(stage: &S, ctx: &PacketContext) -> bool {
    if !stage.is_applicable(ctx) {
        return false;
    }
    if ctx.capture_direction() == CaptureDirection::Egress && !stage.runs_on_egress() {
        return false;
    }
    true
}

#[derive(Debug, Clone)]
pub enum StageOutcome { Continue, Halt, ReleaseBatch(VecDeque<PacketContext>) }

impl PartialEq for StageOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (StageOutcome::ReleaseBatch(_), StageOutcome::ReleaseBatch(_)) => { true }
            (StageOutcome::Continue, StageOutcome::Continue) => { true }
            (StageOutcome::Halt, StageOutcome::Halt) => { true }
            (_, _) => { false }
        }
    }
}

#[derive(Clone)]
pub struct Chain<A: Stage + Clone, B: Stage + Clone> { pub head: A, pub tail: B }
impl<A, B> Stage for Chain<A, B> where A: Stage + Clone, B: Stage + Clone {
    fn runs_on_egress(&self) -> bool {
        self.head.runs_on_egress() || self.tail.runs_on_egress()
    }

    async fn process(&self, ctx: &mut PacketContext, tx: &ExecutionSender) -> StageOutcome {
        let outcome = if stage_should_run(&self.head, ctx) {
            self.head.process(ctx, tx).await
        } else {
            StageOutcome::Continue
        };
        match outcome {
            StageOutcome::Continue => {
                if stage_should_run(&self.tail, ctx) {
                    self.tail.process(ctx, tx).await
                } else {
                    StageOutcome::Continue
                }
            }
            StageOutcome::Halt => {
                let _ = tx.send(ExecutionItem { packet: ctx.clone(), action: ExecutionAction::Drop });
                StageOutcome::Halt
            }
            StageOutcome::ReleaseBatch(packets) => {
                for mut packet in packets {
                    if stage_should_run(&self.tail, &packet) {
                        self.tail.process(&mut packet, tx).await;
                    }
                }
                StageOutcome::Halt
            }
        }
    }
}

#[derive(Clone)]
pub struct ExecutionStage {
    pub tx: ExecutionSender,
}

impl Stage for ExecutionStage {
    async fn process(&self, ctx: &mut PacketContext, _tx: &ExecutionSender) -> StageOutcome {
        tracing::trace!(
            event = "execution.enqueue.forward",
            iface = %ctx.borrow_src_interface(),
            packet_len = ctx.borrow_raw().len(),
            "enqueueing packet for forwarding"
        );
        let _ = self.tx.send(ExecutionItem { packet: ctx.clone(), action: ExecutionAction::Forward });
        StageOutcome::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone)]
    struct PassStage;
    impl Stage for PassStage {
        async fn process(&self, _ctx: &mut PacketContext, _tx: &ExecutionSender) -> StageOutcome {
            StageOutcome::Continue
        }
    }

    #[derive(Clone)]
    struct HaltStage;
    impl Stage for HaltStage {
        async fn process(&self, _ctx: &mut PacketContext, _tx: &ExecutionSender) -> StageOutcome {
            StageOutcome::Halt
        }
    }

    #[derive(Clone)]
    struct ReleaseBatchStage;
    impl Stage for ReleaseBatchStage {
        async fn process(&self, ctx: &mut PacketContext, _tx: &ExecutionSender) -> StageOutcome {
            let mut batch = VecDeque::new();
            batch.push_back(ctx.clone());
            batch.push_back(ctx.clone());
            StageOutcome::ReleaseBatch(batch)
        }
    }

    #[derive(Clone)]
    struct InapplicableStage;
    impl Stage for InapplicableStage {
        fn is_applicable(&self, _ctx: &PacketContext) -> bool { false }

        async fn process(&self, _ctx: &mut PacketContext, _tx: &ExecutionSender) -> StageOutcome {
            panic!("inapplicable stage should not run");
        }
    }

    fn test_packet() -> PacketContext {
        use etherparse::PacketBuilder;
        let mut raw = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(12345, 80, 1, 65535)
            .write(&mut raw, b"test")
            .unwrap();
        PacketContext::from_raw(raw, Arc::from("eth0")).unwrap()
    }

    #[tokio::test]
    async fn execution_stage_emits_forward() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stage = ExecutionStage { tx: tx.clone() };
        let mut ctx = test_packet();

        let outcome = stage.process(&mut ctx, &tx).await;

        assert!(matches!(outcome, StageOutcome::Continue));
        let item = rx.recv().await.unwrap();
        assert!(matches!(item.action, ExecutionAction::Forward));
    }

    #[tokio::test]
    async fn chain_emits_drop_on_halt() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let chain = Chain {
            head: HaltStage,
            tail: PassStage,
        };
        let mut ctx = test_packet();

        let outcome = chain.process(&mut ctx, &tx).await;

        assert!(matches!(outcome, StageOutcome::Halt));
        let item = rx.recv().await.unwrap();
        assert!(matches!(item.action, ExecutionAction::Drop));
    }

    #[tokio::test]
    async fn chain_replays_batch_through_tail() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let chain = Chain {
            head: ReleaseBatchStage,
            tail: ExecutionStage { tx: tx.clone() },
        };
        let mut ctx = test_packet();

        let outcome = chain.process(&mut ctx, &tx).await;

        assert!(matches!(outcome, StageOutcome::Halt));
        
        let item1 = rx.recv().await.unwrap();
        assert!(matches!(item1.action, ExecutionAction::Forward));
        
        let item2 = rx.recv().await.unwrap();
        assert!(matches!(item2.action, ExecutionAction::Forward));
    }

    #[tokio::test]
    async fn chain_skips_inapplicable_tail_stage() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let chain = Chain {
            head: PassStage,
            tail: InapplicableStage,
        };
        let mut ctx = test_packet();

        let outcome = chain.process(&mut ctx, &tx).await;

        assert!(matches!(outcome, StageOutcome::Continue));
    }

    #[tokio::test]
    async fn normal_packet_reaches_execution_stage() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let chain = Chain {
            head: PassStage,
            tail: ExecutionStage { tx: tx.clone() },
        };
        let mut ctx = test_packet();

        chain.process(&mut ctx, &tx).await;

        let item = rx.recv().await.unwrap();
        assert!(matches!(item.action, ExecutionAction::Forward));
    }
}
