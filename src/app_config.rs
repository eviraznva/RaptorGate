use std::env;

use anyhow::Result;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub backend_server_addr: String,
    pub lifecycle_service_addr: String,
    pub firewall_status_bind_addr: String,
    pub redis_url: String,
    pub redis_consumer_group: String,
    pub redis_consumer_name: String,
    pub redis_pending_idle_ms: u64,
    pub redis_max_retry_backoff_ms: u64,
    pub redis_max_delivery_attempts: u32,
    pub redis_dead_letter_stream: String,
    pub snapshot_path: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            backend_server_addr: env_or_default("RG_BACKEND_SERVER_ADDR", "http://127.0.0.1:3001"),
            lifecycle_service_addr: env_or_default(
                "RG_LIFECYCLE_SERVICE_ADDR",
                "http://127.0.0.1:3001",
            ),
            firewall_status_bind_addr: env_or_default(
                "RG_FIREWALL_STATUS_BIND_ADDR",
                "127.0.0.1:3002",
            ),
            redis_url: env_or_default("RG_REDIS_URL", "redis://127.0.0.1:6379"),
            redis_consumer_group: env_or_default(
                "RG_REDIS_CONSUMER_GROUP",
                "firewall-control-plane",
            ),
            redis_consumer_name: env_or_default("RG_REDIS_CONSUMER_NAME", "firewall-1"),
            redis_pending_idle_ms: env_u64_or_default("RG_REDIS_PENDING_IDLE_MS", 30000),
            redis_max_retry_backoff_ms: env_u64_or_default("RG_REDIS_MAX_RETRY_BACKOFF_MS", 30000),
            redis_max_delivery_attempts: env_u32_or_default("RG_REDIS_MAX_DELIVERY_ATTEMPTS", 5),
            redis_dead_letter_stream: env_or_default(
                "RG_REDIS_DEAD_LETTER_STREAM",
                "control-plane.dead-letter",
            ),
            snapshot_path: env_or_default("RG_SNAPSHOT_PATH", "./snapshot/active_config.json"),
        })
    }
}

fn env_or_default(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_u64_or_default(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u32_or_default(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}
