use std::sync::Arc;
use arc_swap::ArcSwap;

#[derive(Debug, Clone, Copy, Default)]
pub enum FirewallOperationMode {
    #[default]
    Normal,
    DegradedLocalSnapshot,
    SafeDeny,
    Resyncing,
}

#[derive(Debug, Clone)]
pub struct FirewallOperationModeHandle {
    inner: Arc<ArcSwap<FirewallOperationMode>>,
}

impl FirewallOperationModeHandle {
    pub fn new(initial: FirewallOperationMode) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub fn load(&self) -> FirewallOperationMode {
        *self.inner.load_full()
    }

    pub fn store(&self, mode: FirewallOperationMode) {
        self.inner.store(Arc::new(mode));
    }

    pub fn is_safe_deny(&self) -> bool {
        matches!(self.load(), FirewallOperationMode::SafeDeny)
    }
}