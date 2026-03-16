use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::app_config::AppConfig;
use crate::control_plane::backend_api::proto::raptorgate::common::FirewallMode;
use crate::control_plane::error::ControlPlaneError;
use crate::control_plane::runtime::state::StatusPublisher;
use crate::control_plane::service;
use crate::policy::compiler;
use crate::policy::runtime::CompiledPolicy;

pub struct ControlPlaneConfig {
    pub grpc_socket_path: String,
    pub firewall_version: String,
    pub heartbeat_interval_secs: u64,
    pub event_buffer: usize,
    pub snapshot_path: Option<String>,
    pub reconnect_initial_backoff_ms: u64,
    pub reconnect_max_backoff_ms: u64,
    pub fallback_block_icmp: bool,
}

impl From<&AppConfig> for ControlPlaneConfig {
    fn from(config: &AppConfig) -> Self {
        Self {
            grpc_socket_path: config.grpc_socket_path.clone(),
            firewall_version: config.firewall_version.clone(),
            heartbeat_interval_secs: config.heartbeat_interval_secs,
            event_buffer: 10_000,
            snapshot_path: Some(config.redb_snapshot_path.clone()),
            reconnect_initial_backoff_ms: 500,
            reconnect_max_backoff_ms: 5_000,
            fallback_block_icmp: config.block_icmp,
        }
    }
}

#[derive(Clone)]
pub struct ControlPlaneHandle {
    status_rx: watch::Receiver<ControlPlaneStatus>,
    policy_rx: watch::Receiver<Arc<CompiledPolicy>>,
}

impl ControlPlaneHandle {
    pub fn status(&self) -> watch::Receiver<ControlPlaneStatus> {
        self.status_rx.clone()
    }

    pub fn policy(&self) -> watch::Receiver<Arc<CompiledPolicy>> {
        self.policy_rx.clone()
    }
}

pub struct ControlPlane {
    handle: ControlPlaneHandle,
    shutdown: CancellationToken,
    join: JoinHandle<Result<(), ControlPlaneError>>,
}

impl ControlPlane {
    pub async fn start(config: ControlPlaneConfig) -> Result<Self, ControlPlaneError> {
        let initial_policy = Arc::new(
            compiler::compile_fallback(config.fallback_block_icmp)
                .map_err(|err| ControlPlaneError::PolicyCompile(err.to_string()))?,
        );

        let (status_tx, status_rx) = watch::channel(ControlPlaneStatus {
            phase: LifecyclePhase::Starting,
            mode: FirewallMode::SafeDeny,
            active_version: None,
            backend_connected: false,
            last_error: None,
        });

        let (policy_tx, policy_rx) = watch::channel(initial_policy);

        let shutdown = CancellationToken::new();

        let join = tokio::spawn(service::run(
            config,
            StatusPublisher::new(status_tx),
            policy_tx,
            shutdown.clone(),
        ));

        Ok(Self {
            handle: ControlPlaneHandle {
                status_rx,
                policy_rx,
            },
            shutdown,
            join,
        })
    }

    pub fn handle(&self) -> ControlPlaneHandle {
        self.handle.clone()
    }

    pub async fn shutdown(self) -> Result<(), ControlPlaneError> {
        self.shutdown.cancel();
        self.join
            .await
            .map_err(|err| ControlPlaneError::Join(err.to_string()))?
    }
}

#[derive(Clone, Debug)]
pub enum LifecyclePhase {
    Starting,
    LoadingSnapshot,
    FetchingInitialConfig,
    Normal,
    Emergency,
    SafeDeny,
    Resyncing,
    Reconnecting,
    Stopped,
}

#[derive(Clone, Debug)]
pub struct ControlPlaneStatus {
    pub phase: LifecyclePhase,
    pub mode: FirewallMode,
    pub active_version: Option<u64>,
    pub backend_connected: bool,
    pub last_error: Option<String>,
}
