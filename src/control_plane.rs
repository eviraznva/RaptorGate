use std::sync::Arc;
use anyhow::Result;

use crate::app_config::AppConfig;
use crate::control_plane::snapshot_store::SnapshotStore;
use crate::control_plane::runtime_firewall_rules::RuntimeFirewallRules;
use crate::control_plane::grpc_client::{GrpcClient, GrpcConnectionConfig};
use crate::control_plane::runtime_firewall_rules_handle::RuntimeRulesHandle;
use crate::control_plane::firewall_rules_sync::FirewallRulesSyncOrchestrator;
use crate::control_plane::firewall_operation_mode::{FirewallOperationMode, FirewallOperationModeHandle};
use crate::control_plane::firewall_status_server::{FirewallStatusGrpcService, FirewallStatusServerState};
use crate::control_plane::redis_transport::{RedisEventConsumer, RedisEventPublisher, RedisTransportConfig};

mod proto_types;
mod grpc_client;
mod redis_events;
mod redis_transport;
mod snapshot_store;
mod firewall_rules_sync;
mod runtime_firewall_rules;
mod firewall_operation_mode;
mod firewall_status_server;
mod runtime_firewall_rules_handle;
mod firewall_runtime_rules_mapper;

pub struct ControlPlane {
    pub runtime_rules: Arc<RuntimeRulesHandle>,
    pub operation_mode: Arc<FirewallOperationModeHandle>,
    orchestrator: Arc<FirewallRulesSyncOrchestrator>,
    redis_consumer: Arc<RedisEventConsumer>,
    redis_publisher: Arc<RedisEventPublisher>,
    firewall_status_bind_addr: String,
}

impl ControlPlane {
    pub fn new(app_config: AppConfig) -> Self {
        let runtime_rules = Arc::new(RuntimeRulesHandle::new(RuntimeFirewallRules::empty()));

        let operation_mode = Arc::new(FirewallOperationModeHandle::new(
            FirewallOperationMode::SafeDeny,
        ));

        let grpc = GrpcClient::new(GrpcConnectionConfig {
            config_service_addr: app_config.backend_server_addr.clone(),
            lifecycle_service_addr: app_config.lifecycle_service_addr.clone(),
        });

        let snapshot_store = Arc::new(SnapshotStore::new(&app_config.snapshot_path));

        let orchestrator = FirewallRulesSyncOrchestrator::new(
            grpc,
            snapshot_store.clone(),
            runtime_rules.clone(),
            operation_mode.clone(),
        );

        let orchestrator = Arc::new(orchestrator);

        let redis_consumer = Arc::new(
            RedisEventConsumer::new(
                RedisTransportConfig {
                    redis_url: app_config.redis_url.clone(),
                    consumer_group: app_config.redis_consumer_group.clone(),
                    consumer_name: app_config.redis_consumer_name.clone(),
                    pending_idle_ms: app_config.redis_pending_idle_ms,
                    max_retry_backoff_ms: app_config.redis_max_retry_backoff_ms,
                    max_delivery_attempts: app_config.redis_max_delivery_attempts,
                    dead_letter_stream: app_config.redis_dead_letter_stream.clone(),
                },
                orchestrator.clone(),
            ),
        );

        let redis_publisher = Arc::new(
            RedisEventPublisher::new(&app_config.redis_url, app_config.redis_consumer_name.clone()),
        );

        Self {
            orchestrator,
            runtime_rules,
            operation_mode,
            redis_consumer,
            redis_publisher,
            firewall_status_bind_addr: app_config.firewall_status_bind_addr,
        }
    }

    pub async fn startup(&self) -> Result<()> {
        self.orchestrator.startup().await
    }

    pub fn redis_publisher(&self) -> Arc<RedisEventPublisher> {
        self.redis_publisher.clone()
    }

    pub async fn run_redis_consumer(&self) -> Result<()> {
        self.redis_consumer.run().await
    }

    pub async fn run_firewall_status_server(&self) -> Result<()> {
        FirewallStatusGrpcService::new(FirewallStatusServerState {
            runtime_rules: self.runtime_rules.clone(),
            operation_mode: self.operation_mode.clone(),
        }).serve(&self.firewall_status_bind_addr).await
    }
}
