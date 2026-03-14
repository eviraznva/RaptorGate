use uuid::Uuid;
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Context, Result};

use crate::control_plane::firewall_operation_mode::{
    FirewallOperationMode,
    FirewallOperationModeHandle,
};

use crate::control_plane::grpc_client::GrpcClient;
use crate::control_plane::snapshot_store::SnapshotStore;
use crate::control_plane::runtime_firewall_rules_handle::RuntimeRulesHandle;
use crate::control_plane::proto_types::raptorgate::config::ConfigSnapshotRequestReason;

#[derive(Debug, Clone, Copy)]
pub enum SyncTrigger {
    Startup,
    ConfigBundleChanged,
    Resync,
    Rollback { requested_version: u64 },
}

impl SyncTrigger {
    pub fn reason(self) -> ConfigSnapshotRequestReason {
        match self {
            Self::Startup => ConfigSnapshotRequestReason::Startup,
            Self::ConfigBundleChanged => ConfigSnapshotRequestReason::ConfigChange,
            Self::Resync => ConfigSnapshotRequestReason::Resync,
            Self::Rollback { .. } => ConfigSnapshotRequestReason::Rollback,
        }
    }

    pub fn requested_version(self) -> Option<u64> {
        match self {
            Self::Rollback { requested_version } => Some(requested_version),
            _ => None,
        }
    }
}

pub struct FirewallRulesSyncOrchestrator {
    grpc: Mutex<GrpcClient>,
    snapshot_store: Arc<SnapshotStore>,
    runtime_rules: Arc<RuntimeRulesHandle>,
    operation_mode: Arc<FirewallOperationModeHandle>,
}

impl FirewallRulesSyncOrchestrator {
    pub fn new(
        grpc: GrpcClient,
        snapshot_store: Arc<SnapshotStore>,
        runtime_rules: Arc<RuntimeRulesHandle>,
        operation_mode: Arc<FirewallOperationModeHandle>,
    ) -> Self {
        Self {
            grpc: Mutex::new(grpc),
            snapshot_store,
            runtime_rules,
            operation_mode,
        }
    }

    pub async fn startup(&self) -> Result<()> {
        println!("Starting config sync: startup");

        match self.sync_from_backend(SyncTrigger::Startup, None).await {
            Ok(()) => Ok(()),
            Err(_err) => {
                println!("Startup sync from backend failed, trying local snapshot");
                self.try_activate_local_snapshot_on_startup().await
            }
        }
    }

    pub async fn on_config_bundle_changed(&self, correlation_id: Uuid) -> Result<()> {
        println!("Received config.bundle.changed");
        self.sync_from_backend(SyncTrigger::ConfigBundleChanged, Some(correlation_id)).await
    }

    pub async fn on_resync_available(&self, correlation_id: Uuid) -> Result<()> {
        println!("Received config.resync.available");

        self.operation_mode.store(FirewallOperationMode::Resyncing);

        let result = self.sync_from_backend(SyncTrigger::Resync, Some(correlation_id)).await;

        if let Err(_err) = &result {
            println!("Resync failed, returning to degraded mode");

            self.operation_mode.store(FirewallOperationMode::DegradedLocalSnapshot);
        }

        result
    }
    
    pub async fn on_rollback_requested(&self, requested_version: u64, correlation_id: Uuid) -> Result<()> {
        println!("Received rollback request");

        self.sync_from_backend(SyncTrigger::Rollback { requested_version }, Some(correlation_id)).await
    }

    async fn sync_from_backend(&self, trigger: SyncTrigger, correlation_id: Option<Uuid>) -> Result<()> {
        let current_version = {
            let rules = self.runtime_rules.load();
            let version = rules.config_version();

            if version == 0 { None } else { Some(version) }
        };
        
        let correlation_id = correlation_id.unwrap_or_else(Uuid::new_v4);

        let mut grpc = self.grpc.lock().await;

        let fetch_outcome = grpc
            .fetch_runtime_rules(
                current_version,
                trigger.requested_version(),
                correlation_id,
                trigger.reason(),
            )
            .await
            .with_context(|| format!("Failed to fetch runtime rules for {:?}", trigger))?;

        let new_version = fetch_outcome.config_version;

        if matches!(trigger, SyncTrigger::Resync)
            && !fetch_outcome.configuration_changed
            && fetch_outcome.runtime_rules.is_none()
        {
            self.operation_mode.store(FirewallOperationMode::Normal);

            if let Some(previous_version) = current_version {
                let _ = grpc
                    .report_resync_no_changes(previous_version, new_version, correlation_id)
                    .await;
            }

            println!("Resync completed with no configuration changes");

            return Ok(());
        }

        let runtime_rules = fetch_outcome
            .runtime_rules
            .context("Backend response did not include runtime rules payload")?;

        self.snapshot_store
            .save(&runtime_rules)
            .context("Failed to persist runtime snapshot before swap")?;

        self.runtime_rules.store(runtime_rules);

        self.operation_mode.store(FirewallOperationMode::Normal);

        match trigger {
            SyncTrigger::Startup => {
                let _ = grpc.report_startup_success(new_version, correlation_id).await;
            }
            SyncTrigger::ConfigBundleChanged => {
                let _ = grpc.report_apply_success(new_version, correlation_id).await;
            }
            SyncTrigger::Resync => {
                let previous_version = current_version.unwrap_or(new_version);
                let _ = grpc.report_resync_success(previous_version, new_version, correlation_id).await;
            }
            SyncTrigger::Rollback { requested_version } => {
                let previous_version = current_version.unwrap_or(new_version);
                let _ = grpc.report_rollback_success(previous_version, requested_version, correlation_id).await;
            }
        }

        println!("Runtime rules swapped successfully");

        Ok(())
    }

    async fn try_activate_local_snapshot_on_startup(&self) -> Result<()> {
        match self.snapshot_store.load()? {
            Some(local_rules) => {
                self.runtime_rules.store(local_rules);
                self.operation_mode.store(FirewallOperationMode::DegradedLocalSnapshot);

                println!("Backend unavailable, activated local snapshot");

                Ok(())
            }
            None => {
                self.operation_mode.store(FirewallOperationMode::SafeDeny);

                println!("Backend unavailable and no local snapshot found, staying in safe_deny");

                Ok(())
            }
        }
    }
}
