use std::time::Duration;

use crate::config::AppConfig;

/// Konfiguracja nowego runtime IPC po stronie firewalla.
#[derive(Debug, Clone)]
pub struct FirewallIpcConfig {
    pub sync_socket_path: String,
    pub async_socket_path: String,
    pub heartbeat_interval: Duration,
    pub async_reconnect_interval: Duration,
    pub event_queue_capacity: usize,
}

impl From<&AppConfig> for FirewallIpcConfig {
    fn from(config: &AppConfig) -> Self {
        Self {
            sync_socket_path: config.sync_ipc_socket_path.clone(),
            async_socket_path: config.async_ipc_socket_path.clone(),
            heartbeat_interval: Duration::from_secs(config.heartbeat_interval_secs),
            async_reconnect_interval: Duration::from_secs(2),
            event_queue_capacity: config.event_queue_capacity,
        }
    }
}
