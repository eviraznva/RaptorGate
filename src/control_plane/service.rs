use std::cmp::min;
use std::panic;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::control_plane::api::{ControlPlaneConfig, LifecyclePhase};
use crate::control_plane::backend_api::client::BackendApiClient;
use crate::control_plane::backend_api::event_codec::{
    BE_CONFIG_CHANGED, BE_HEARTBEAT_ACK, BE_RESYNC_REQUESTED, FW_HEARTBEAT, FW_METRICS,
    current_timestamp, decode_backend_payload, encode_firewall_event, encode_policy_activated,
    encode_policy_failed, encode_resync_confirmed,
};
use crate::control_plane::backend_api::proto::raptorgate::common::{
    FirewallMode, PolicyFailureCode,
};
use crate::control_plane::backend_api::proto::raptorgate::config::{
    ConfigRequestReason, ConfigResponse, GetConfigRequest,
};
use crate::control_plane::backend_api::proto::raptorgate::events::{
    ConfigChangedEvent, HeartbeatAck, HeartbeatEvent, PolicyActivatedEvent, PolicyFailedEvent,
    ResyncConfirmedEvent, ResyncRequestedEvent,
};
use crate::control_plane::backend_api::proto::raptorgate::telemetry::MetricsBatch;
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
        panic!("DEV MODE: Control plane is running with a policy override. This should only be used for testing and development purposes, and not in production environments.");
        tracing::info!("DEV MODE: Applying policy override and skipping control plane syncing.");

        let override_policy = compiler::compile_override(dsl)
            .map_err(|err| ControlPlaneError::PolicyCompile(err.to_string()))?;

        // let override_policy = compiler::compile_override(dsl).expect("ERROR: couldnt compile override policy");

        let _ = policy_tx.send(Arc::new(override_policy));
        status.set_phase(LifecyclePhase::Normal);

        shutdown.cancelled().await;
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
            Ok((client, next_active)) => {
                reconnect_backoff_ms = config.reconnect_initial_backoff_ms;
                active_config = Some(next_active);

                if let Some(current) = active_config.clone() {
                    let session_result = run_event_session(
                        &config,
                        &status,
                        &policy_tx,
                        snapshot_store.as_ref(),
                        client,
                        current,
                        &shutdown,
                    )
                    .await?;

                    active_config = Some(session_result);
                    status.set_backend_connected(false);
                    if !shutdown.is_cancelled() {
                        status.set_phase(LifecyclePhase::Reconnecting);
                    }
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "Bootstrap failed");
                status.set_last_error(err.to_string());
                status.set_backend_connected(false);

                match active_config.as_ref() {
                    Some(snapshot_active) => {
                        tracing::warn!(version = snapshot_active.version, "Backend unavailable — entering EMERGENCY mode (snapshot from Redb)");
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
                        tracing::warn!("No snapshot available — entering SAFE-DENY mode (drop all)");
                        status.set_phase(LifecyclePhase::SafeDeny);
                        status.set_mode(FirewallMode::SafeDeny);
                        status.set_version(None);
                        publish_safe_deny(&policy_tx)?;
                    }
                }
            }
        }

        tracing::info!(backoff_ms = reconnect_backoff_ms, "Reconnecting after backoff...");
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
) -> Result<(BackendApiClient, ActiveConfig), ControlPlaneError> {
    status.set_phase(LifecyclePhase::FetchingInitialConfig);

    tracing::info!(socket = %config.grpc_socket_path, "Connecting to backend...");
    let mut client = BackendApiClient::connect(&config.grpc_socket_path).await
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
            known_version: existing.as_ref().map(|cfg| cfg.version as i32),
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

    tracing::info!(version = active_config.version, "Config loaded, entering NORMAL mode");
    Ok((client, active_config))
}

async fn run_event_session(
    config: &ControlPlaneConfig,
    status: &StatusPublisher,
    policy_tx: &watch::Sender<Arc<CompiledPolicy>>,
    snapshot_store: Option<&Arc<dyn SnapshotStore>>,
    mut client: BackendApiClient,
    mut active_config: ActiveConfig,
    shutdown: &CancellationToken,
) -> Result<ActiveConfig, ControlPlaneError> {
    let mut stream_channels = client.open_event_stream(config.event_buffer);
    let session_started = Instant::now();

    send_heartbeat(
        &stream_channels.outbound,
        config,
        FirewallMode::Normal,
        active_config.version,
        session_started.elapsed().as_secs(),
    )
    .await;

    match stream_channels.opened.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(ControlPlaneError::ConfigFetch(err)),
        Err(err) => return Err(ControlPlaneError::Join(err.to_string())),
    }

    let mut interval = tokio::time::interval(Duration::from_secs(config.heartbeat_interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                status.set_phase(LifecyclePhase::Stopped);
                status.set_backend_connected(false);
                return Ok(active_config);
            }
            _ = interval.tick() => {
                send_heartbeat(
                    &stream_channels.outbound,
                    config,
                    FirewallMode::Normal,
                    active_config.version,
                    session_started.elapsed().as_secs(),
                ).await;
                let _ = stream_channels.outbound.send(encode_firewall_event(FW_METRICS, MetricsBatch::default())).await;
            }
            next_event = stream_channels.inbound.recv() => {
                match next_event {
                    Some(event) => {
                        match event.r#type.as_str() {
                            BE_HEARTBEAT_ACK => {
                                let _ = decode_backend_payload::<HeartbeatAck>(&event);
                            }
                            BE_CONFIG_CHANGED => {
                                let payload = decode_backend_payload::<ConfigChangedEvent>(&event)
                                    .map_err(|err| ControlPlaneError::Delta(err.to_string()))?;
                                let previous_version = active_config.version;
                                match reconcile_config_change(
                                    &mut client,
                                    config,
                                    snapshot_store,
                                    policy_tx,
                                    &mut active_config,
                                    payload.correlation_id.clone(),
                                    ConfigRequestReason::ConfigChanged,
                                    PolicySource::Backend,
                                ).await {
                                    Ok(changed) => {
                                        status.set_phase(LifecyclePhase::Normal);
                                        status.set_mode(FirewallMode::Normal);
                                        status.set_version(Some(active_config.version));
                                        if changed {
                                            let _ = stream_channels.outbound.send(encode_policy_activated(PolicyActivatedEvent {
                                                config_id: payload.config_id,
                                                config_version: active_config.version,
                                                correlation_id: payload.correlation_id,
                                                activated_at: Some(current_timestamp()),
                                            })).await;
                                        }
                                        tracing::info!(from = previous_version, to = active_config.version, "Config change reconciled");
                                    }
                                    Err(err) => {
                                        let _ = stream_channels.outbound.send(encode_policy_failed(PolicyFailedEvent {
                                            config_id: payload.config_id,
                                            config_version: active_config.version,
                                            correlation_id: payload.correlation_id,
                                            failure_code: PolicyFailureCode::Unspecified as i32,
                                            failure_message: err.to_string(),
                                            validation_errors: Vec::new(),
                                            failed_at: Some(current_timestamp()),
                                        })).await;
                                        return Err(err);
                                    }
                                }
                            }
                            BE_RESYNC_REQUESTED => {
                                let payload = decode_backend_payload::<ResyncRequestedEvent>(&event)
                                    .map_err(|err| ControlPlaneError::Delta(err.to_string()))?;
                                let previous_version = active_config.version;
                                status.set_phase(LifecyclePhase::Resyncing);
                                status.set_mode(FirewallMode::Resyncing);
                                let changed = reconcile_config_change(
                                    &mut client,
                                    config,
                                    snapshot_store,
                                    policy_tx,
                                    &mut active_config,
                                    payload.correlation_id.clone(),
                                    ConfigRequestReason::Resync,
                                    PolicySource::Backend,
                                ).await?;

                                status.set_phase(LifecyclePhase::Normal);
                                status.set_mode(FirewallMode::Normal);
                                status.set_version(Some(active_config.version));

                                let _ = stream_channels.outbound.send(encode_resync_confirmed(ResyncConfirmedEvent {
                                    previous_version,
                                    current_version: active_config.version,
                                    correlation_id: payload.correlation_id,
                                    no_change: !changed,
                                    confirmed_at: Some(current_timestamp()),
                                })).await;
                            }
                            other => {
                                tracing::warn!(event_type = other, "Unknown backend event type");
                            }
                        }
                    }
                    None => return Ok(active_config),
                }
            }
        }
    }
}

async fn reconcile_config_change(
    client: &mut BackendApiClient,
    config: &ControlPlaneConfig,
    snapshot_store: Option<&Arc<dyn SnapshotStore>>,
    policy_tx: &watch::Sender<Arc<CompiledPolicy>>,
    active_config: &mut ActiveConfig,
    correlation_id: String,
    reason: ConfigRequestReason,
    source: PolicySource,
) -> Result<bool, ControlPlaneError> {
    let response = client
        .get_active_config(GetConfigRequest {
            correlation_id,
            reason: reason as i32,
            known_versions: Some(active_config.section_versions.clone()),
            known_version: Some(active_config.version as i32),
        })
        .await?;

    let changed = response.configuration_changed;
    let next_config = merge_response(Some(active_config.clone()), response)?;
    persist_snapshot(snapshot_store, &next_config)?;
    publish_active_config(policy_tx, &next_config, config.fallback_block_icmp, source)?;
    *active_config = next_config;
    Ok(changed)
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

async fn send_heartbeat(
    fw_tx: &mpsc::Sender<
        crate::control_plane::backend_api::proto::raptorgate::events::FirewallEvent,
    >,
    config: &ControlPlaneConfig,
    mode: FirewallMode,
    active_config_version: u64,
    uptime_seconds: u64,
) {
    let _ = fw_tx
        .send(encode_firewall_event(
            FW_HEARTBEAT,
            HeartbeatEvent {
                firewall_version: config.firewall_version.clone(),
                mode: mode as i32,
                active_config_version,
                uptime_seconds,
            },
        ))
        .await;
}
