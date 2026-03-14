use uuid::Uuid;
use std::sync::Arc;
use std::time::SystemTime;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use anyhow::{Context, Result as AnyhowResult};

use crate::control_plane::firewall_operation_mode::{FirewallOperationMode, FirewallOperationModeHandle};
use crate::control_plane::proto_types::raptorgate::common::{HealthStatus, FirewallOperatingMode as ProtoFirewallOperatingMode};
use crate::control_plane::proto_types::raptorgate::status::{
    firewall_status_service_server::{FirewallStatusService, FirewallStatusServiceServer},
    FirewallStatusResponse,
    GetFirewallStatusRequest,
};

use crate::control_plane::runtime_firewall_rules_handle::RuntimeRulesHandle;

#[derive(Clone)]
pub struct FirewallStatusServerState {
    pub runtime_rules: Arc<RuntimeRulesHandle>,
    pub operation_mode: Arc<FirewallOperationModeHandle>,
}

#[derive(Clone)]
pub struct FirewallStatusGrpcService {
    state: FirewallStatusServerState,
}

impl FirewallStatusGrpcService {
    pub fn new(state: FirewallStatusServerState) -> Self {
        Self { state }
    }

    pub async fn serve(self, bind_addr: &str) -> AnyhowResult<()> {
        let addr = bind_addr
            .parse()
            .with_context(|| format!("Invalid firewall status bind address: {bind_addr}"))?;

        Server::builder()
            .add_service(FirewallStatusServiceServer::new(self))
            .serve(addr)
            .await
            .context("Firewall status gRPC server failed")
    }
}

#[tonic::async_trait]
impl FirewallStatusService for FirewallStatusGrpcService {
    async fn get_firewall_status(&self, request: Request<GetFirewallStatusRequest>) 
        -> Result<Response<FirewallStatusResponse>, Status> {
        let request = request.into_inner();
        
        let correlation_id = if request.correlation_id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            request.correlation_id
        };

        let operating_mode = self.state.operation_mode.load();
        let runtime_rules = self.state.runtime_rules.load();
        
        let active_config_version = runtime_rules.config_version();

        let using_local_snapshot = matches!(operating_mode, FirewallOperationMode::DegradedLocalSnapshot);
        
        let local_snapshot_version = using_local_snapshot.then_some(active_config_version);
        
        let resync_required = matches!(operating_mode, FirewallOperationMode::DegradedLocalSnapshot | FirewallOperationMode::SafeDeny);

        let response = FirewallStatusResponse {
            health_status: map_health_status(operating_mode) as i32,
            operating_mode: map_operating_mode(operating_mode) as i32,
            active_config_version,
            using_local_snapshot,
            local_snapshot_version,
            resync_required,
            updated_at: Some(prost_types::Timestamp::from(SystemTime::now())),
            status_message: build_status_message(operating_mode, active_config_version),
            correlation_id,
        };

        Ok(Response::new(response))
    }
}

fn map_operating_mode(mode: FirewallOperationMode) -> ProtoFirewallOperatingMode {
    match mode {
        FirewallOperationMode::Normal => ProtoFirewallOperatingMode::Normal,
        FirewallOperationMode::DegradedLocalSnapshot => ProtoFirewallOperatingMode::DegradedLocalSnapshot,
        FirewallOperationMode::SafeDeny => ProtoFirewallOperatingMode::SafeDeny,
        FirewallOperationMode::Resyncing => ProtoFirewallOperatingMode::Resyncing,
    }
}

fn map_health_status(mode: FirewallOperationMode) -> HealthStatus {
    match mode {
        FirewallOperationMode::Normal => HealthStatus::Healthy,
        FirewallOperationMode::DegradedLocalSnapshot | FirewallOperationMode::Resyncing => HealthStatus::Degraded,
        FirewallOperationMode::SafeDeny => HealthStatus::Unavailable,
    }
}

fn build_status_message(mode: FirewallOperationMode, active_config_version: u64) -> String {
    match mode {
        FirewallOperationMode::Normal => format!("Firewall running with active config version {active_config_version}"),
        FirewallOperationMode::DegradedLocalSnapshot => {
            format!("Firewall running in degraded mode from local snapshot version {active_config_version}")
        }
        FirewallOperationMode::SafeDeny => "Firewall is in safe deny mode and awaits configuration".to_string(),
        FirewallOperationMode::Resyncing => format!("Firewall is resynchronizing configuration from version {active_config_version}"),
    }
}
