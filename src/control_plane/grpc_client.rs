use uuid::Uuid;
use tonic::Request;
use std::time::SystemTime;
use anyhow::{Context, Result};
use tonic::transport::{Channel, Endpoint};

use crate::control_plane::firewall_runtime_rules_mapper::map_config_snapshot_response_to_runtime_rules;

use crate::control_plane::proto_types::raptorgate::config::{
    config_service_client::ConfigServiceClient, ConfigSnapshotRequestReason, GetConfigSnapshotRequest
};

use crate::control_plane::proto_types::raptorgate::lifecycle::{ResyncResultRequest, ResyncStatus, RollbackResultRequest, StartupResultRequest, StartupStatus, lifecycle_service_client::LifecycleServiceClient, ConfigurationApplyResultRequest, ConfigurationApplyStatus, RollbackStatus};

use crate::control_plane::runtime_firewall_rules::RuntimeFirewallRules;

#[derive(Debug, Clone)]
pub struct GrpcConnectionConfig {
    pub config_service_addr: String,
    pub lifecycle_service_addr: String,
}

#[derive(Clone)]
pub struct GrpcClient {
    cfg: GrpcConnectionConfig,
    config: Option<ConfigServiceClient<Channel>>,
    lifecycle: Option<LifecycleServiceClient<Channel>>,
}

pub struct FetchRuntimeRulesOutcome {
    pub runtime_rules: Option<RuntimeFirewallRules>,
    pub config_version: u64,
    pub configuration_changed: bool,
}

impl GrpcClient {
    pub fn new(cfg: GrpcConnectionConfig) -> Self {
        Self {
            cfg,
            config: None,
            lifecycle: None,
        }
    }

    pub async fn fetch_runtime_rules(
        &mut self,
        current_config_version: Option<u64>,
        requested_config_version: Option<u64>,
        correlation_id: Uuid,
        reason: ConfigSnapshotRequestReason,
    ) -> Result<FetchRuntimeRulesOutcome> {
        self.ensure_connected().await?;

        let request = GetConfigSnapshotRequest {
            current_config_version,
            requested_config_version,
            correlation_id: correlation_id.to_string(),
            reason: reason as i32,
        };

        let response = self.config.as_mut().unwrap()
            .get_config_snapshot(Request::new(request)).await?.into_inner();

        let runtime_rules = if response.active_configuration.is_some() {
            Some(
                map_config_snapshot_response_to_runtime_rules(&response)
                    .context("Failed to map config snapshot response to runtime rules")?,
            )
        } else {
            None
        };

        Ok(FetchRuntimeRulesOutcome {
            runtime_rules,
            config_version: response.config_version,
            configuration_changed: response.configuration_changed,
        })
    }

    pub async fn report_startup_success(&mut self, config_version: u64, correlation_id: Uuid) -> Result<()> {
        self.ensure_connected().await?;

        let request = StartupResultRequest {
            status: StartupStatus::Success as i32,
            config_version: Some(config_version),
            failure_code: String::new(),
            failure_message: String::new(),
            correlation_id: correlation_id.to_string(),
            reported_at: Some(prost_types::Timestamp::from(SystemTime::now())),
        };

        self.lifecycle.as_mut().unwrap().report_startup_result(Request::new(request)).await?;

        Ok(())
    }

    pub async fn report_apply_success(&mut self, config_version:  u64, correlation_id: Uuid) -> Result<()> {
        self.ensure_connected().await?;

        let request = ConfigurationApplyResultRequest {
            config_version,
            status: ConfigurationApplyStatus::Success as i32,
            failure_code: String::new(),
            failure_message: String::new(),
            validation_errors: Vec::new(),
            correlation_id: correlation_id.to_string(),
            reported_at: Some(prost_types::Timestamp::from(SystemTime::now())),
        };

        self.lifecycle.as_mut().unwrap().report_configuration_apply_result(Request::new(request)).await?;

        Ok(())
    }

    pub async fn report_resync_success(&mut self, previous: u64, current: u64, correlation_id: Uuid) -> Result<()> {
        self.ensure_connected().await?;

        let request = ResyncResultRequest {
            previous_config_version: previous,
            current_config_version: current,
            status: ResyncStatus::Success as i32,
            failure_code: String::new(),
            failure_message: String::new(),
            validation_errors: Vec::new(),
            correlation_id: correlation_id.to_string(),
            reported_at: Some(prost_types::Timestamp::from(SystemTime::now())),
        };

        self.lifecycle.as_mut().unwrap().report_resync_result(Request::new(request)).await?;

        Ok(())
    }

    pub async fn report_resync_no_changes(&mut self, previous: u64, current: u64, correlation_id: Uuid) -> Result<()> {
        self.ensure_connected().await?;

        let request = ResyncResultRequest {
            previous_config_version: previous,
            current_config_version: current,
            status: ResyncStatus::NoChanges as i32,
            failure_code: String::new(),
            failure_message: String::new(),
            validation_errors: Vec::new(),
            correlation_id: correlation_id.to_string(),
            reported_at: Some(prost_types::Timestamp::from(SystemTime::now())),
        };

        self.lifecycle.as_mut().unwrap().report_resync_result(Request::new(request)).await?;

        Ok(())
    }

    pub async fn report_rollback_success(&mut self, previous: u64, target: u64, correlation_id: Uuid) -> Result<()> {
        self.ensure_connected().await?;

        let request = RollbackResultRequest {
            previous_config_version: previous,
            rolled_back_to_config_version: target,
            status: RollbackStatus::Success as i32,
            failure_code: String::new(),
            failure_message: String::new(),
            validation_errors: Vec::new(),
            correlation_id: correlation_id.to_string(),
            reported_at: Some(prost_types::Timestamp::from(SystemTime::now())),
        };

        self.lifecycle.as_mut().unwrap().report_rollback_result(Request::new(request)).await?;

        Ok(())
    }

    async fn ensure_connected(&mut self) -> Result<(), tonic::transport::Error> {
        let config_missing = self.config.is_none();
        let lifecycle_missing = self.lifecycle.is_none();

        if config_missing {
            let channel = Endpoint::from_shared(self.cfg.config_service_addr.clone())?
                .connect().await?;

            self.config = Some(ConfigServiceClient::new(channel));
        }

        if lifecycle_missing {
            let channel = Endpoint::from_shared(self.cfg.lifecycle_service_addr.clone())?
                .connect().await?;

            self.lifecycle = Some(LifecycleServiceClient::new(channel));
        }

        Ok(())
    }
}
