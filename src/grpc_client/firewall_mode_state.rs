use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use crate::grpc_client::proto_types::raptorgate::common::FirewallMode;

#[derive(Clone)]
pub struct FirewallModeState {
    mode: Arc<AtomicU8>,
    config_version: Arc<AtomicU64>,
}

impl FirewallModeState {
    pub fn new(initial: FirewallMode) -> Self {
        Self {
            mode: Arc::new(AtomicU8::new(initial as u8)),
            config_version: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn get(&self) -> FirewallMode { self.mode.load(Ordering::Relaxed).try_into().unwrap_or(FirewallMode::Unspecified) }
    pub fn set(&self, mode: FirewallMode) { self.mode.store(mode as u8, Ordering::Relaxed); }

    pub fn get_config_version(&self) -> u64 { self.config_version.load(Ordering::Relaxed) }
    pub fn set_config_version(&self, v: u64) { self.config_version.store(v, Ordering::Relaxed); }
}