use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{RwLock, watch};

use crate::policy::runtime::CompiledPolicy;
use crate::control_plane::ipc::ipc_message::FirewallMode;
use crate::control_plane::messages::events::heartbeat_event::HeartbeatEvent;
use crate::control_plane::messages::responses::get_status_response::GetStatusResponse;

/// Migawka stanu publikowana przez runtime IPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallIpcStatus {
    pub mode: FirewallMode,
    pub loaded_revision_id: u64,
    pub last_error_code: u32,
}

impl Default for FirewallIpcStatus {
    fn default() -> Self {
        Self {
            mode: FirewallMode::Normal,
            loaded_revision_id: 0,
            last_error_code: 0,
        }
    }
}

/// Współdzielony stan odczytywany przez handlery IPC.
#[derive(Clone)]
pub struct FirewallState {
    started_at: Instant,
    status: Arc<RwLock<FirewallIpcStatus>>,
    policy_rx: watch::Receiver<Arc<CompiledPolicy>>,
}

impl FirewallState {
    pub fn new(policy_rx: watch::Receiver<Arc<CompiledPolicy>>) -> Self {
        Self {
            started_at: Instant::now(),
            status: Arc::new(RwLock::new(FirewallIpcStatus::default())),
            policy_rx,
        }
    }

    /// Zwraca watch z aktualną polityką dla data-plane.
    pub fn policy_receiver(&self) -> watch::Receiver<Arc<CompiledPolicy>> {
        self.policy_rx.clone()
    }

    /// Aktualizuje bieżący status firewalla.
    pub async fn update_status(&self, update: impl FnOnce(&mut FirewallIpcStatus)) {
        let mut guard = self.status.write().await;
        
        update(&mut guard);
    }

    /// Buduje payload odpowiedzi `GET_STATUS`.
    pub async fn build_status_response(&self) -> GetStatusResponse {
        let status = self.status.read().await.clone();
        
        GetStatusResponse {
            mode: status.mode,
            loaded_revision_id: status.loaded_revision_id,
            policy_hash: 0,
            uptime_sec: self.started_at.elapsed().as_secs(),
            last_error_code: status.last_error_code,
        }
    }

    /// Buduje payload eventu `HEARTBEAT`.
    pub async fn build_heartbeat_event(&self) -> HeartbeatEvent {
        let status = self.status.read().await.clone();
        
        HeartbeatEvent {
            timestamp_ms: current_timestamp_ms(),
            mode: status.mode,
            loaded_revision_id: status.loaded_revision_id,
            policy_hash: 0,
            uptime_sec: self.started_at.elapsed().as_secs(),
            last_error_code: status.last_error_code,
        }
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
