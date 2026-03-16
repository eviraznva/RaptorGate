use tokio::sync::watch;

use crate::control_plane::backend_api::proto::raptorgate::common::FirewallMode;
use crate::control_plane::{ControlPlaneStatus, LifecyclePhase};

#[derive(Clone)]
pub struct StatusPublisher {
    tx: watch::Sender<ControlPlaneStatus>,
}

impl StatusPublisher {
    pub fn new(tx: watch::Sender<ControlPlaneStatus>) -> Self {
        Self { tx }
    }

    pub fn update(&self, update: impl FnOnce(&mut ControlPlaneStatus)) {
        let mut next = self.tx.borrow().clone();
        update(&mut next);
        let _ = self.tx.send(next);
    }

    pub fn set_phase(&self, phase: LifecyclePhase) {
        self.update(|status| status.phase = phase);
    }

    pub fn set_mode(&self, mode: FirewallMode) {
        self.update(|status| status.mode = mode);
    }

    pub fn set_version(&self, version: Option<u64>) {
        self.update(|status| status.active_version = version);
    }

    pub fn set_backend_connected(&self, backend_connected: bool) {
        self.update(|status| status.backend_connected = backend_connected);
    }

    pub fn set_last_error(&self, error: impl Into<String>) {
        let error = error.into();
        self.update(|status| status.last_error = Some(error));
    }

    pub fn clear_last_error(&self) {
        self.update(|status| status.last_error = None);
    }
}
