use std::sync::Arc;

use tokio::sync::RwLock;

use crate::app_config::AppConfig;
use crate::grpc_client::event_type::EventType;
use crate::grpc_client::active_config::ActiveConfig;
use crate::grpc_client::event_dispatcher::EventDispatcher;
use crate::grpc_client::firewall_mode_state::FirewallModeState;
use crate::grpc_client::event_stream_manager::EventStreamManager;
use crate::grpc_client::client::{current_timestamp, make_firewall_event, GrpcClient};
use crate::grpc_client::proto_types::raptorgate::{
    common::{FirewallMode, PolicyFailureCode},
    config::{ConfigRequestReason, GetConfigRequest},
    events::{ConfigChangedEvent, PolicyActivatedEvent, PolicyFailedEvent},
};

pub struct BackendConnection {
    pub mode: FirewallModeState,
    pub event_manager: EventStreamManager,
    pub active_config: Arc<RwLock<ActiveConfig>>,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendConnectionError {
    #[error("połączenie UDS: {0}")]
    Connect(#[from] tonic::transport::Error),
    #[error("pobieranie konfiguracji: {0}")]
    ConfigFetch(tonic::Status),
    #[error("otwarcie EventStream: {0}")]
    EventStream(tonic::Status),
}

impl BackendConnection {
    pub async fn startup(config: &AppConfig) -> Result<Self, BackendConnectionError> {
        let mode = FirewallModeState::new(FirewallMode::SafeDeny);
        
        let mut client = GrpcClient::connect(&config.grpc_socket_path).await?;
        
        let correlation_id = uuid::Uuid::now_v7().to_string();
        
        let resp = client
            .get_active_config(GetConfigRequest {
                correlation_id: correlation_id.clone(),
                reason: ConfigRequestReason::Startup as i32,
                known_versions: None,
                known_version: None,
            }).await
            .map_err(BackendConnectionError::ConfigFetch)?;

        let config_version = resp.config_version;
        let active_config = Arc::new(RwLock::new(ActiveConfig::from_response(resp)));

        mode.set(FirewallMode::Normal);
        mode.set_config_version(config_version);

        tracing::info!(version = config_version, "Konfiguracja pobrana, tryb NORMAL");
        
        let (fw_tx, be_rx) = client.open_event_stream(10_000);
        
        let handler_client = client.clone();
        
        let handler_config = Arc::clone(&active_config);
        
        let handler_mode = mode.clone();
        
        let handler_fw_tx = fw_tx.clone();
        
        let fw_version = config.firewall_version.clone();

        let dispatcher =
            EventDispatcher::new().on::<ConfigChangedEvent, _, _>(move |event| {
                let mut client = handler_client.clone();
                
                let config = Arc::clone(&handler_config);
                
                let mode = handler_mode.clone();
                
                let fw_tx = handler_fw_tx.clone();
                
                let fw_version = fw_version.clone();
                let correlation = event.correlation_id.clone();

                async move {
                    tracing::info!(correlation_id = %correlation, "config_changed — re-fetch");

                    let known_versions = {
                        let guard = config.read().await;
                        Some(guard.section_versions.clone())
                    };

                    match client
                        .get_active_config(GetConfigRequest {
                            correlation_id: correlation.clone(),
                            reason: ConfigRequestReason::ConfigChanged as i32,
                            known_versions,
                            known_version: None,
                        }).await
                    {
                        Ok(resp) => {
                            let new_version = resp.config_version;
                            
                            config.write().await.merge_delta(resp);
                            mode.set_config_version(new_version);

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
            });
        
        let event_manager = EventStreamManager::start(
            fw_tx,
            be_rx,
            mode.clone(),
            config.firewall_version.clone(),
            config.heartbeat_interval_secs,
            dispatcher,
        ).await
        .map_err(|s| BackendConnectionError::EventStream(s))?;

        Ok(Self {
            mode,
            event_manager,
            active_config,
        })
    }
}
