use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::policy::runtime::CompiledPolicy;

pub struct PolicyStore {
    current: ArcSwap<CompiledPolicy>,
}

impl PolicyStore {
    pub fn new(initial: Arc<CompiledPolicy>) -> Arc<Self> {
        Arc::new(Self {
            current: ArcSwap::from(initial),
        })
    }

    pub fn from_watch(
        policy_rx: watch::Receiver<Arc<CompiledPolicy>>,
    ) -> (Arc<Self>, JoinHandle<()>) {
        let initial = policy_rx.borrow().clone();
        let store = Self::new(initial);
        let store_task = Arc::clone(&store);

        let join = tokio::spawn(async move {
            let mut policy_rx = policy_rx;

            while policy_rx.changed().await.is_ok() {
                let next_policy = policy_rx.borrow().clone();
                store_task.current.store(next_policy);
            }
        });

        (store, join)
    }

    pub fn load(&self) -> Arc<CompiledPolicy> {
        self.current.load_full()
    }
}