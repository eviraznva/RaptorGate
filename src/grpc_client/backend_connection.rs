use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;

use crate::app_config::AppConfig;
use crate::grpc_client::event_type::EventType;
use crate::grpc_client::active_config::ActiveConfig;
use crate::grpc_client::config_snapshot::ConfigSnapshot;
use crate::grpc_client::event_dispatcher::EventDispatcher;
use crate::grpc_client::firewall_mode_state::FirewallModeState;
use crate::grpc_client::event_stream_manager::EventStreamManager;
use crate::grpc_client::client::{current_timestamp, make_firewall_event, GrpcClient};
use crate::grpc_client::proto_types::raptorgate::{
    common::{FirewallMode, PolicyFailureCode},
    config::{ConfigRequestReason, ConfigResponse, GetConfigRequest},
    events::{
        ConfigChangedEvent, FirewallEvent, PolicyActivatedEvent, PolicyFailedEvent,
        ResyncConfirmedEvent, ResyncRequestedEvent,
    },
};

pub struct BackendConnection {
    pub mode: FirewallModeState,
    pub active_config: Arc<RwLock<ActiveConfig>>,
    pub snapshot: Option<Arc<ConfigSnapshot>>,
}

impl BackendConnection {
    pub async fn startup(config: &AppConfig) -> Self {
        let snapshot: Option<Arc<ConfigSnapshot>> = match ConfigSnapshot::open(&config.redb_snapshot_path) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                tracing::warn!(error = %e, "Redb niedostępne — snapshot wyłączony");
                None
            }
        };

        // --- próba normalnego startu ---
        'normal: {
            let mut client = match GrpcClient::connect(&config.grpc_socket_path).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "gRPC niedostępny przy starcie");
                    break 'normal;
                }
            };

            let resp = match client.get_active_config(GetConfigRequest {
                correlation_id: uuid::Uuid::now_v7().to_string(),
                reason: ConfigRequestReason::Startup as i32,
                known_versions: None,
                known_version: None,
            }).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "GetActiveConfig nieudany przy starcie");
                    break 'normal;
                }
            };

            // --- NORMAL ---
            let config_version = resp.config_version;
            let active_config = Arc::new(RwLock::new(ActiveConfig::from_response(resp)));
            let mode = FirewallModeState::new(FirewallMode::Normal);
            mode.set_config_version(config_version);

            if let Some(ref snap) = snapshot {
                snap.clone().save_bg(active_config.read().await.to_config_response());
            }

            tracing::info!(version = config_version, "Konfiguracja pobrana, tryb NORMAL");

            let (fw_tx, be_rx) = client.open_event_stream(10_000);
            let dispatcher = build_dispatcher(
                client,
                Arc::clone(&active_config),
                mode.clone(),
                fw_tx.clone(),
                config.firewall_version.clone(),
                snapshot.clone(),
            );

            match EventStreamManager::start(
                fw_tx,
                be_rx,
                mode.clone(),
                config.firewall_version.clone(),
                config.heartbeat_interval_secs,
                dispatcher,
            ).await {
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "EventStream nieudany"),
            }

            return Self { mode, active_config, snapshot };
        }

        // --- EMERGENCY lub SAFE-DENY ---
        let (active_config, mode) = match snapshot.as_ref().and_then(|s| s.load()) {
            Some(resp) => {
                let version = resp.config_version;
                let ac = Arc::new(RwLock::new(ActiveConfig::from_response(resp)));
                let m = FirewallModeState::new(FirewallMode::Emergency);
                m.set_config_version(version);
                tracing::warn!(version, "Backend niedostępny — tryb EMERGENCY (snapshot z Redb)");
                (ac, m)
            }
            None => {
                let ac = Arc::new(RwLock::new(ActiveConfig::from_response(ConfigResponse::default())));
                let m = FirewallModeState::new(FirewallMode::SafeDeny);
                tracing::warn!("Brak snapshotu — tryb SAFE-DENY (DROP wszystkiego)");
                (ac, m)
            }
        };

        spawn_reconnect_task(
            config.grpc_socket_path.clone(),
            config.firewall_version.clone(),
            config.heartbeat_interval_secs,
            Arc::clone(&active_config),
            mode.clone(),
            snapshot.clone(),
        );

        Self { mode, active_config, snapshot }
    }
}

fn build_dispatcher(
    client: GrpcClient,
    active_config: Arc<RwLock<ActiveConfig>>,
    mode: FirewallModeState,
    fw_tx: Sender<FirewallEvent>,
    fw_version: String,
    snapshot: Option<Arc<ConfigSnapshot>>,
) -> EventDispatcher {
    // ConfigChangedEvent handler
    let cc_client = client.clone();
    let cc_config = Arc::clone(&active_config);
    let cc_mode = mode.clone();
    let cc_fw_tx = fw_tx.clone();
    let cc_fw_version = fw_version.clone();
    let cc_snapshot = snapshot.clone();

    // ResyncRequestedEvent handler
    let rr_client = client.clone();
    let rr_config = Arc::clone(&active_config);
    let rr_mode = mode.clone();
    let rr_fw_tx = fw_tx.clone();
    let rr_snapshot = snapshot.clone();

    EventDispatcher::new()
        .on::<ConfigChangedEvent, _, _>(move |event| {
            let mut client = cc_client.clone();
            let config = Arc::clone(&cc_config);
            let mode = cc_mode.clone();
            let fw_tx = cc_fw_tx.clone();
            let fw_version = cc_fw_version.clone();
            let correlation = event.correlation_id.clone();
            let snap = cc_snapshot.clone();

            async move {
                tracing::info!(correlation_id = %correlation, "config_changed — re-fetch");

                let known_versions = {
                    let guard = config.read().await;
                    Some(guard.section_versions.clone())
                };

                match client.get_active_config(GetConfigRequest {
                    correlation_id: correlation.clone(),
                    reason: ConfigRequestReason::ConfigChanged as i32,
                    known_versions,
                    known_version: None,
                }).await {
                    Ok(resp) => {
                        let new_version = resp.config_version;
                        config.write().await.merge_delta(resp);
                        mode.set_config_version(new_version);

                        if let Some(ref s) = snap {
                            s.clone().save_bg(config.read().await.to_config_response());
                        }

                        tracing::info!(
                            version = new_version,
                            fw_version = %fw_version,
                            "Polityka zaktualizowana po config_changed"
                        );

                        let _ = fw_tx.try_send(make_firewall_event(
                            PolicyActivatedEvent::TYPE,
                            PolicyActivatedEvent {
                                config_version: new_version,
                                correlation_id: correlation,
                                activated_at: Some(current_timestamp()),
                                ..Default::default()
                            },
                        ));
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "re-fetch konfiguracji nieudany");

                        let _ = fw_tx.try_send(make_firewall_event(
                            PolicyFailedEvent::TYPE,
                            PolicyFailedEvent {
                                correlation_id: correlation,
                                failure_message: e.message().to_string(),
                                failure_code: PolicyFailureCode::Unspecified as i32,
                                failed_at: Some(current_timestamp()),
                                ..Default::default()
                            },
                        ));
                    }
                }
            }
        })
        .on::<ResyncRequestedEvent, _, _>(move |event| {
            let mut client = rr_client.clone();
            let config = Arc::clone(&rr_config);
            let mode = rr_mode.clone();
            let fw_tx = rr_fw_tx.clone();
            let snap = rr_snapshot.clone();
            let correlation = event.correlation_id.clone();

            async move {
                tracing::info!(correlation_id = %correlation, "resync_requested — re-fetch konfiguracji");

                let (previous_version, known_versions) = {
                    let guard = config.read().await;
                    (mode.get_config_version(), Some(guard.section_versions.clone()))
                };

                mode.set(FirewallMode::Resyncing);

                match client.get_active_config(GetConfigRequest {
                    correlation_id: correlation.clone(),
                    reason: ConfigRequestReason::Resync as i32,
                    known_versions,
                    known_version: None,
                }).await {
                    Ok(resp) => {
                        let new_version = resp.config_version;
                        config.write().await.merge_delta(resp);
                        mode.set_config_version(new_version);

                        if let Some(ref s) = snap {
                            s.clone().save_bg(config.read().await.to_config_response());
                        }

                        let _ = fw_tx.try_send(make_firewall_event(
                            ResyncConfirmedEvent::TYPE,
                            ResyncConfirmedEvent {
                                previous_version,
                                current_version: new_version,
                                correlation_id: correlation,
                                no_change: previous_version == new_version,
                                confirmed_at: Some(current_timestamp()),
                            },
                        ));

                        mode.set(FirewallMode::Normal);
                        tracing::info!(version = new_version, "Resync zakończony, tryb NORMAL");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "GetActiveConfig podczas resync nieudany");
                        mode.set(FirewallMode::Emergency);
                    }
                }
            }
        })
}

fn spawn_reconnect_task(
    grpc_socket_path: String,
    firewall_version: String,
    heartbeat_interval_secs: u64,
    active_config: Arc<RwLock<ActiveConfig>>,
    mode: FirewallModeState,
    snapshot: Option<Arc<ConfigSnapshot>>,
) {
    tokio::spawn(async move {
        let mut delay_secs = 1u64;

        loop {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            delay_secs = (delay_secs * 2).min(60);

            tracing::info!(delay_secs, "Próba reconnect z backendem...");

            let mut client = match GrpcClient::connect(&grpc_socket_path).await {
                Ok(c) => {
                    delay_secs = 1;
                    c
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Reconnect nieudany");
                    continue;
                }
            };

            let previous_version = mode.get_config_version();
            let reason = if previous_version > 0 {
                ConfigRequestReason::Emergency
            } else {
                ConfigRequestReason::Startup
            };
            let known_versions = if previous_version > 0 {
                let guard = active_config.read().await;
                Some(guard.section_versions.clone())
            } else {
                None
            };

            let correlation = uuid::Uuid::now_v7().to_string();
            mode.set(FirewallMode::Resyncing);

            let resp = match client.get_active_config(GetConfigRequest {
                correlation_id: correlation.clone(),
                reason: reason as i32,
                known_versions,
                known_version: None,
            }).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "GetActiveConfig podczas reconnect nieudany");
                    mode.set(if previous_version > 0 {
                        FirewallMode::Emergency
                    } else {
                        FirewallMode::SafeDeny
                    });
                    continue;
                }
            };

            let new_version = resp.config_version;
            {
                let mut guard = active_config.write().await;
                if previous_version > 0 {
                    guard.merge_delta(resp);
                } else {
                    *guard = ActiveConfig::from_response(resp);
                }
            }
            mode.set_config_version(new_version);

            if let Some(ref snap) = snapshot {
                snap.clone().save_bg(active_config.read().await.to_config_response());
            }

            let (fw_tx, be_rx) = client.open_event_stream(10_000);
            let dispatcher = build_dispatcher(
                client,
                Arc::clone(&active_config),
                mode.clone(),
                fw_tx.clone(),
                firewall_version.clone(),
                snapshot.clone(),
            );

            let _ = fw_tx.try_send(make_firewall_event(
                ResyncConfirmedEvent::TYPE,
                ResyncConfirmedEvent {
                    previous_version,
                    current_version: new_version,
                    correlation_id: correlation,
                    no_change: previous_version == new_version,
                    confirmed_at: Some(current_timestamp()),
                },
            ));

            match EventStreamManager::start(
                fw_tx,
                be_rx,
                mode.clone(),
                firewall_version.clone(),
                heartbeat_interval_secs,
                dispatcher,
            ).await {
                Ok(_) => {
                    mode.set(FirewallMode::Normal);
                    tracing::info!(version = new_version, "Resync zakończony, tryb NORMAL");
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "EventStream nieudany po reconnect");
                    mode.set(FirewallMode::Emergency);
                    // kontynuuj pętlę
                }
            }
        }
    });
}
