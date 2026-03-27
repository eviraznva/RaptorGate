use std::cmp::min;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::control_plane::api::{ControlPlaneConfig, LifecyclePhase};
use crate::control_plane::backend_api::client::BackendApiClient;
use crate::control_plane::backend_api::proto::raptorgate::common::FirewallMode;
use crate::control_plane::backend_api::proto::raptorgate::config::{
    ConfigRequestReason, ConfigResponse, GetConfigRequest,
};
use crate::control_plane::config::active_config::ActiveConfig;
use crate::control_plane::error::ControlPlaneError;
use crate::control_plane::runtime::state::StatusPublisher;
use crate::control_plane::snapshot::redb::RedbSnapshotStore;
use crate::control_plane::snapshot::store::SnapshotStore;
use crate::policy::compiler;
use crate::policy::runtime::{CompiledPolicy, PolicySource};

pub async fn run(
    config: ControlPlaneConfig,
    status: StatusPublisher,
    policy_tx: watch::Sender<Arc<CompiledPolicy>>,
    shutdown: CancellationToken,
) -> Result<(), ControlPlaneError> {
    if let Some(ref dsl) = config.dev_policy_override {
        tracing::warn!("DEV MODE: Control plane is running with a policy override. This should only be used for testing and development purposes, and not in production environments.");
        tracing::info!("DEV MODE: Applying policy override and skipping control plane syncing.");

        let override_policy = compiler::compile_override(dsl)
            .map_err(|err| ControlPlaneError::PolicyCompile(err.to_string()))?;

        tracing::info!("DEV MODE: Override policy compiled successfully");
        let _ = policy_tx.send(Arc::new(override_policy));
        tracing::info!("DEV MODE: Override policy activated, entering Normal phase");
        status.set_phase(LifecyclePhase::Normal);
        tracing::info!("DEV MODE: Control plane idle — backend connection disabled in override mode");

        shutdown.cancelled().await;
        tracing::info!("DEV MODE: Shutdown signal received, exiting");
        return Ok(());
    }

    let snapshot_store = open_snapshot_store(&config)?;
    let mut active_config = load_snapshot(snapshot_store.as_ref(), &config, &status, &policy_tx)?;
    let mut reconnect_backoff_ms = config.reconnect_initial_backoff_ms;

    loop {
        if shutdown.is_cancelled() {
            status.set_phase(LifecyclePhase::Stopped);
            status.set_backend_connected(false);
            return Ok(());
        }

        match connect_and_bootstrap(
            &config,
            &status,
            &policy_tx,
            snapshot_store.as_ref(),
            active_config.clone(),
        )
        .await
        {
            Ok(next_active) => {
                reconnect_backoff_ms = config.reconnect_initial_backoff_ms;
                active_config = Some(next_active);
                status.set_backend_connected(false);

                // Event session removed — control plane is legacy.
                // Wait for shutdown or reconnect trigger.
                shutdown.cancelled().await;
                status.set_phase(LifecyclePhase::Stopped);
                return Ok(());
            }
            Err(err) => {
                tracing::warn!(error = %err, "Bootstrap failed");
                status.set_last_error(err.to_string());
                status.set_backend_connected(false);

                match active_config.as_ref() {
                    Some(snapshot_active) => {
                        tracing::warn!(
                            version = snapshot_active.version,
                            "Backend unavailable — entering EMERGENCY mode (snapshot from Redb)"
                        );
                        status.set_phase(LifecyclePhase::Emergency);
                        status.set_mode(FirewallMode::Emergency);
                        status.set_version(Some(snapshot_active.version));
                        publish_active_config(
                            &policy_tx,
                            snapshot_active,
                            config.fallback_block_icmp,
                            PolicySource::Snapshot,
                        )?;
                    }
                    None => {
                        tracing::warn!(
                            "No snapshot available — entering ALLOW-ALL mode (dev/test)"
                        );
                        status.set_phase(LifecyclePhase::SafeDeny);
                        status.set_mode(FirewallMode::SafeDeny);
                        status.set_version(None);
                        publish_fallback(&policy_tx, false)?;
                    }
                }
            }
        }

        tracing::info!(
            backoff_ms = reconnect_backoff_ms,
            "Reconnecting after backoff..."
        );
        tokio::select! {
            _ = shutdown.cancelled() => {
                status.set_phase(LifecyclePhase::Stopped);
                status.set_backend_connected(false);
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(reconnect_backoff_ms)) => {}
        }

        reconnect_backoff_ms = min(
            reconnect_backoff_ms.saturating_mul(2),
            config.reconnect_max_backoff_ms,
        );
    }
}

fn open_snapshot_store(
    config: &ControlPlaneConfig,
) -> Result<Option<Arc<dyn SnapshotStore>>, ControlPlaneError> {
    match config.snapshot_path.as_deref() {
        Some(path) => {
            let store: Arc<dyn SnapshotStore> = Arc::new(RedbSnapshotStore::open(path)?);
            Ok(Some(store))
        }
        None => Ok(None),
    }
}

fn load_snapshot(
    snapshot_store: Option<&Arc<dyn SnapshotStore>>,
    config: &ControlPlaneConfig,
    status: &StatusPublisher,
    policy_tx: &watch::Sender<Arc<CompiledPolicy>>,
) -> Result<Option<ActiveConfig>, ControlPlaneError> {
    let Some(snapshot_store) = snapshot_store else {
        return Ok(None);
    };

    status.set_phase(LifecyclePhase::LoadingSnapshot);

    let Some(response) = snapshot_store.load()? else {
        return Ok(None);
    };

    let active_config = ActiveConfig::from_response(response);
    publish_active_config(
        policy_tx,
        &active_config,
        config.fallback_block_icmp,
        PolicySource::Snapshot,
    )?;
    status.set_mode(FirewallMode::Emergency);
    status.set_phase(LifecyclePhase::Emergency);
    status.set_version(Some(active_config.version));
    Ok(Some(active_config))
}

async fn connect_and_bootstrap(
    config: &ControlPlaneConfig,
    status: &StatusPublisher,
    policy_tx: &watch::Sender<Arc<CompiledPolicy>>,
    snapshot_store: Option<&Arc<dyn SnapshotStore>>,
    existing: Option<ActiveConfig>,
) -> Result<ActiveConfig, ControlPlaneError> {
    status.set_phase(LifecyclePhase::FetchingInitialConfig);

    tracing::info!(socket = %config.grpc_socket_path, "Connecting to backend...");
    let mut client = BackendApiClient::connect(&config.grpc_socket_path)
        .await
        .inspect_err(|e| tracing::warn!(error = %e, "Backend connection failed"))?;
    tracing::info!("Connected to backend, fetching config...");

    let request_reason = if existing.is_some() {
        ConfigRequestReason::Emergency as i32
    } else {
        ConfigRequestReason::Startup as i32
    };
    let correlation_id = uuid::Uuid::now_v7().to_string();
    let response = client
        .get_active_config(GetConfigRequest {
            correlation_id,
            reason: request_reason,
            known_versions: existing.as_ref().map(|cfg| cfg.section_versions.clone()),
        })
        .await?;

    let active_config = merge_response(existing, response)?;
    persist_snapshot(snapshot_store, &active_config)?;
    publish_active_config(
        policy_tx,
        &active_config,
        config.fallback_block_icmp,
        if active_config.version > 0 {
            PolicySource::Backend
        } else {
            PolicySource::SnapshotThenBackend
        },
    )?;

    status.clear_last_error();
    status.set_phase(LifecyclePhase::Normal);
    status.set_mode(FirewallMode::Normal);
    status.set_version(Some(active_config.version));
    status.set_backend_connected(true);

    tracing::info!(
        version = active_config.version,
        "Config loaded, entering NORMAL mode"
    );
    Ok(active_config)
}

fn merge_response(
    existing: Option<ActiveConfig>,
    response: ConfigResponse,
) -> Result<ActiveConfig, ControlPlaneError> {
    match existing {
        Some(current) if !response.configuration_changed => Ok(current),
        Some(current) => current
            .apply_delta(response)
            .map_err(|err| ControlPlaneError::Delta(err.to_string())),
        None => Ok(ActiveConfig::from_response(response)),
    }
}

fn publish_active_config(
    policy_tx: &watch::Sender<Arc<CompiledPolicy>>,
    active_config: &ActiveConfig,
    block_icmp: bool,
    source: PolicySource,
) -> Result<(), ControlPlaneError> {
    let policy = compiler::compile_from_active_config(active_config, block_icmp, source)
        .map_err(|err| ControlPlaneError::PolicyCompile(err.to_string()))?;
    let _ = policy_tx.send(Arc::new(policy));
    Ok(())
}

fn publish_fallback(
    policy_tx: &watch::Sender<Arc<CompiledPolicy>>,
    block_icmp: bool,
) -> Result<(), ControlPlaneError> {
    let policy = compiler::compile_fallback(block_icmp)
        .map_err(|err| ControlPlaneError::PolicyCompile(err.to_string()))?;
    let _ = policy_tx.send(Arc::new(policy));
    Ok(())
}

#[allow(dead_code)]
fn publish_safe_deny(
    policy_tx: &watch::Sender<Arc<CompiledPolicy>>,
) -> Result<(), ControlPlaneError> {
    let policy = compiler::compile_safe_deny()
        .map_err(|err| ControlPlaneError::PolicyCompile(err.to_string()))?;
    let _ = policy_tx.send(Arc::new(policy));
    Ok(())
}

fn persist_snapshot(
    snapshot_store: Option<&Arc<dyn SnapshotStore>>,
    active_config: &ActiveConfig,
) -> Result<(), ControlPlaneError> {
    if let Some(snapshot_store) = snapshot_store {
        snapshot_store.save(&active_config.to_config_response())?;
    }
    Ok(())
}
