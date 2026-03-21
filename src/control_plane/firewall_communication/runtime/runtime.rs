use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use tokio_util::sync::CancellationToken;

use crate::policy::compiler;
use crate::control_plane::types::ipc_status::IpcStatus;
use crate::control_plane::types::firewall_mode::FirewallMode;
use crate::control_plane::firewall_communication::sync::listener;
use crate::control_plane::errors::revision_store_error::RevisionStoreError;
use crate::control_plane::firewall_communication::publish::async_publisher;
use crate::control_plane::firewall_communication::config::FirewallIpcConfig;
use crate::control_plane::firewall_communication::runtime::revision_store::RevisionStore;
use crate::control_plane::firewall_communication::publish::event_ring::{EventRingHandle, channel};

use crate::control_plane::firewall_communication::runtime::state::{
    ActiveRevision, FirewallState, FirewallRuntimeState
};

/// Handle do obserwacji stanu i polityki firewalla.
#[derive(Clone)]
pub struct FirewallIpcHandle {
    state_rx: watch::Receiver<Arc<FirewallRuntimeState>>,
    event_ring: EventRingHandle
}

impl FirewallIpcHandle {
    pub fn state(&self) -> watch::Receiver<Arc<FirewallRuntimeState>> {
        self.state_rx.clone()
    }

    pub fn event_ring(&self) -> EventRingHandle {
        self.event_ring.clone()
    }
}

/// Główny runtime firewall-side IPC.
pub struct FirewallIpcRuntime {
    handle: FirewallIpcHandle,
    shutdown: CancellationToken,
    joins: Vec<JoinHandle<()>>,
}

impl FirewallIpcRuntime {
    /// Uruchamia nowy runtime IPC firewalla.
    #[tracing::instrument(skip(config), fields(
        sync_socket = %config.sync_socket_path,
        async_socket = %config.async_socket_path,
        config_store_path = %config.config_store_path
    ))]
    pub async fn start(config: FirewallIpcConfig, block_icmp: bool) 
        -> Result<Self, Box<dyn std::error::Error + Send + Sync>> 
    {
        info!(
            sync_socket = %config.sync_socket_path,
            async_socket = %config.async_socket_path,
            config_store_path = %config.config_store_path,
            heartbeat_interval_ms = config.heartbeat_interval.as_millis(),
            async_reconnect_interval_ms = config.async_reconnect_interval.as_millis(),
            event_queue_capacity = config.event_queue_capacity,
            block_icmp,
            "Starting firewall IPC runtime"
        );

        let initial_state =
            build_initial_runtime_state(&config.config_store_path, block_icmp).await?;

        debug!(
            mode = ?initial_state.mode,
            revision_id = initial_state.active_revision.revision_id(),
            policy_hash = initial_state.active_revision.policy_hash(),
            last_error_code = initial_state.last_error_code,
            "Built initial firewall runtime state"
        );

        let (state_tx, state_rx) =
            watch::channel(initial_state);
        
        let (event_ring, event_rx) = channel(config.event_queue_capacity);

        let state = FirewallState::new(
            RevisionStore::new(config.config_store_path.clone()),
            state_tx,
        );

        let shutdown = CancellationToken::new();

        let sync_join = tokio::spawn({
            let state = state.clone();
            
            let shutdown = shutdown.clone();
            
            let socket_path = config.sync_socket_path.clone();
            
            async move {
                if let Err(err) = listener::run(socket_path, state, shutdown).await {
                    tracing::error!(error = %err, "Sync IPC listener stopped with error");
                }
            }
        });

        let async_join = tokio::spawn({
            let state = state.clone();
            
            let shutdown = shutdown.clone();
            
            let config = config.clone();
            let event_rx = event_rx;
            
            async move {
                async_publisher::run(config, state, event_rx, shutdown).await;
            }
        });

        Ok(Self {
            handle: FirewallIpcHandle {
                state_rx,
                event_ring,
            },
            shutdown,
            joins: vec![sync_join, async_join],
        })
    }

    pub fn handle(&self) -> FirewallIpcHandle {
        self.handle.clone()
    }

    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Stopping firewall IPC runtime");
        
        self.shutdown.cancel();
        
        for join in self.joins {
            let _ = join.await;
        }

        info!("Firewall IPC runtime stopped");
        
        Ok(())
    }
}

#[tracing::instrument(fields(config_store_path = config_store_path))]
async fn build_initial_runtime_state(
    config_store_path: &str,
    block_icmp: bool,
) -> Result<Arc<FirewallRuntimeState>, Box<dyn std::error::Error + Send + Sync>> {
    let fallback_policy = Arc::new(compiler::compile_fallback(block_icmp)?);

    let fallback_revision = Arc::new(ActiveRevision::fallback(fallback_policy));

    let revision_store = RevisionStore::new(config_store_path.to_string());

    debug!(
        config_store_path,
        block_icmp,
        "Attempting startup bootstrap from active policy revision"
    );

    match revision_store.load_current_active_revision().await {
        Ok(active_revision) => {
            info!(
                revision_id = active_revision.revision_id(),
                policy_hash = active_revision.policy_hash(),
                policy_count = active_revision.policy_count(),
                config_store_path,
                "Bootstrapped firewall runtime from active policy revision"
            );

            Ok(Arc::new(FirewallRuntimeState {
                mode: FirewallMode::Normal,
                active_revision,
                last_error_code: 0,
            }))
        }
        Err(err) => {
            let code = u32::from(map_revision_store_error(&err));

            warn!(
                error = %err,
                config_store_path = config_store_path,
                fallback_revision_id = fallback_revision.revision_id(),
                "Failed to load active policy.bin during startup, falling back to compiled defaults"
            );

            Ok(Arc::new(FirewallRuntimeState {
                mode: FirewallMode::Degraded,
                active_revision: fallback_revision,
                last_error_code: code,
            }))
        }
    }
}

fn map_revision_store_error(err: &RevisionStoreError) -> IpcStatus {
    match err {
        RevisionStoreError::RevisionMismatch { .. } => IpcStatus::ErrPolicyRevisionMismatch,
        RevisionStoreError::ReadActiveLink(_)
        | RevisionStoreError::InvalidActiveTarget { .. }
        | RevisionStoreError::InvalidRevisionDirectory { .. }
        | RevisionStoreError::ReadPolicy(_)
        | RevisionStoreError::ParseRgpf(_) => IpcStatus::ErrPolicyLoadFailed,
    }
}

#[cfg(test)]
mod runtime_tests {
    use tokio::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::build_initial_runtime_state;

    use crate::control_plane::types::ipc_status::IpcStatus;
    use crate::control_plane::types::firewall_mode::FirewallMode;
    use crate::policy::rgpf::test_helpers::{build_policy_bin, TEST_POLICY_HASH, TEST_POLICY_SOURCE};


    static NEXT_TEST_DIR_ID: AtomicU64 = AtomicU64::new(1);

    #[tokio::test]
    async fn startup_uses_active_revision_from_store_when_available() {
        let root = create_test_dir();

        let versions_dir = root.join("versions");

        let revision_dir = versions_dir.join("320");

        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();

        fs::write(revision_dir.join("policy.bin"), build_policy_bin(320, TEST_POLICY_SOURCE)).await.unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let state = build_initial_runtime_state(root.to_str().unwrap(), false).await.unwrap();

        assert_eq!(state.mode, FirewallMode::Normal);
        assert_eq!(state.last_error_code, 0);
        assert_eq!(state.active_revision.revision_id(), 320);
        assert_eq!(state.active_revision.policy_hash(), TEST_POLICY_HASH);
    }

    #[tokio::test]
    async fn startup_falls_back_and_sets_degraded_when_active_revision_is_missing() {
        let root = create_test_dir();

        let state = build_initial_runtime_state(root.to_str().unwrap(), false)
            .await.unwrap();

        assert_eq!(state.mode, FirewallMode::Degraded);
        assert_eq!(state.last_error_code, u32::from(IpcStatus::ErrPolicyLoadFailed));
        assert_eq!(state.active_revision.policy_hash(), 0);
    }

    #[tokio::test]
    async fn startup_uses_revision_mismatch_code_when_header_revision_differs_from_active_target() {
        let root = create_test_dir();

        let versions_dir = root.join("versions");

        let revision_dir = versions_dir.join("320");

        let active_link = root.join("active");

        fs::create_dir_all(&revision_dir).await.unwrap();

        fs::write(revision_dir.join("policy.bin"), build_policy_bin(321, TEST_POLICY_SOURCE)).await.unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/320", &active_link).unwrap();

        let state = build_initial_runtime_state(root.to_str().unwrap(), false)
            .await.unwrap();

        assert_eq!(state.mode, FirewallMode::Degraded);
        assert_eq!(state.last_error_code, u32::from(IpcStatus::ErrPolicyRevisionMismatch));
        assert_eq!(state.active_revision.revision_id(), 0);
        assert_eq!(state.active_revision.policy_hash(), 0);
    }

    fn create_test_dir() -> PathBuf {
        let id = NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);

        let path = std::env::temp_dir().join(format!("rg-runtime-tests-{id}"));

        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();

        path
    }
}
