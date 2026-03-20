use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use crate::grpc_client::proto_types::raptorgate::common::FirewallMode;

#[derive(Clone)]
pub struct FirewallModeState(Arc<AtomicU8>);

impl FirewallModeState {
    pub fn new(initial: FirewallMode) -> Self {
        Self(Arc::new(AtomicU8::new(initial as u8)))
    }

    pub fn get(&self) -> FirewallMode {
        FirewallMode::try_from(self.0.load(Ordering::Relaxed) as i32)
            .unwrap_or(FirewallMode::Unspecified)
    }

    pub fn set(&self, mode: FirewallMode) {
        self.0.store(mode as u8, Ordering::Relaxed);
    }
}