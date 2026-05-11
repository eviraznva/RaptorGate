use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::config::provider::AppConfigProvider;
use crate::data_plane::dns_inspection::config::DnsInspectionConfig;
use crate::data_plane::dns_inspection::dns_inspection::DnsInspection;
use crate::data_plane::dns_inspection::provider::DnsInspectionConfigProvider;
use crate::nat::config::NatConfig;
use crate::data_plane::ips::config::IpsConfig;
use crate::data_plane::ips::ips::Ips;
use crate::data_plane::ips::provider::IpsConfigProvider;
use crate::nat::{NatConfigProvider, NatEngine};
use crate::factory_reset::{safe_app_config, FactoryResetOptions, FactoryResetReport};
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::identity::{IdentitySessionHandler, IdentitySessionStore};
use crate::metrics::{MetricsCollector, MetricsService};
use crate::nat::config::NatRules;
use crate::policy::engine::PolicyEngine;
use crate::policy::provider::{default_drop_policy, PolicyManager};
use crate::policy::{Policy, PolicyId};
use crate::proto::common::CertificateType;
use crate::proto::services::firewall_query_service_server::{
    FirewallQueryService, FirewallQueryServiceServer,
};
use crate::proto::services::firewall_config_snapshot_service_server::{
    FirewallConfigSnapshotService, FirewallConfigSnapshotServiceServer,
};
use crate::proto::services::firewall_metrics_service_server::FirewallMetricsServiceServer;
use crate::proto::services::identity_session_service_server::IdentitySessionServiceServer;
use crate::proto::services::{
    GetNatBindingsRequest, GetNatBindingsResponse,
    GetPinningBypassRequest, GetPinningBypassResponse, GetPinningStatsRequest,
    GetPinningStatsResponse, GetPoliciesRequest, GetPoliciesResponse, GetPolicyRequest,
    GetPolicyResponse, GetZonePairRequest, GetZonePairResponse, GetZonePairsRequest, GetZonePairsResponse,
    GetZoneRequest, GetZoneResponse, GetZonesRequest, GetZonesResponse,
    FactoryResetRequest, FactoryResetResponse, GetSystemTimeRequest, GetSystemTimeResponse,
    PushActiveConfigSnapshotRequest, PushActiveConfigSnapshotResponse, SetInterfaceStateRequest,
    SetInterfaceStateResponse, UpdatePhysicalInterfacePropertiesRequest,
    UpdatePhysicalInterfacePropertiesResponse,
};
use crate::tls::pinning_detector::PinningDetector;
use crate::tls::cert_storage::clear_ca_files;
use crate::tls::{EchTlsPolicy, ServerKeyStore, TlsDecisionEngine};
use crate::tls::decryption_mirror::{DecryptionMirror, DecryptionMirrorConfig};
use crate::validation::validate_bundle;
use crate::zones::Zone;
use crate::interfaces::{InterfaceController, InterfaceMonitor};
use crate::zones::provider::{ZonePairProvider, ZoneProvider};
use crate::zones::{ZoneInterfaceId, ZonePair, ZoneInterface};

pub struct QueryServer<PolicySwap, Monitor, Controller>
where
    PolicySwap: PolicyManager + Send + Sync,
    Monitor: InterfaceMonitor + Send + Sync,
    Controller: InterfaceController + Send + Sync,
{
    handler: QueryHandler<PolicySwap, Monitor, Controller>,
    identity_handler: IdentitySessionHandler,
    socket_path: String,
    shutdown: CancellationToken,
}

impl<PolicySwap, Monitor, Controller> QueryServer<PolicySwap, Monitor, Controller>
where
    PolicySwap: PolicyManager + Send + Sync + 'static,
    Monitor: InterfaceMonitor + Send + Sync + 'static,
    Controller: InterfaceController + Send + Sync + 'static,
{
    pub fn new(
        handler: QueryHandler<PolicySwap, Monitor, Controller>,
        identity_sessions: Arc<IdentitySessionStore>,
        socket_path: impl Into<String>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            handler,
            identity_handler: IdentitySessionHandler::new(identity_sessions),
            socket_path: socket_path.into(),
            shutdown,
        }
    }

    pub async fn serve(self) {
        if let Err(e) = prepare_socket(&self.socket_path) {
            tracing::error!(socket = self.socket_path, error = %e, "failed to prepare query socket");
            return;
        }

        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(socket = self.socket_path, error = %e, "failed to bind query socket");
                return;
            }
        };

        tracing::info!(
            event = "grpc.query_service.listening",
            socket = self.socket_path,
            "FirewallQueryService listening"
        );

        let incoming = UnixListenerStream::new(listener);

        if let Err(e) = tonic::transport::Server::builder()
            .add_service(FirewallQueryServiceServer::new(self.handler.clone()))
            .add_service(FirewallMetricsServiceServer::new(MetricsService::new(
                Arc::clone(&self.handler.metrics_collector),
                Arc::clone(&self.handler.conntrack),
            )))
            .add_service(FirewallConfigSnapshotServiceServer::new(self.handler))
            .add_service(IdentitySessionServiceServer::new(self.identity_handler))
            .serve_with_incoming_shutdown(incoming, self.shutdown.cancelled())
            .await
        {
            tracing::error!(error = %e, "FirewallQueryService server error");
        }

        cleanup_socket(&self.socket_path);
    }
}

pub struct QueryHandler<PolicySwap, Monitor, Controller>
where
    PolicySwap: PolicyManager,
    Monitor: InterfaceMonitor,
    Controller: InterfaceController,
{
    pub tcp_tracker: Arc<TcpSessionTracker>,
    pub nat_engine: Arc<NatEngine>,
    pub nat_store: Arc<NatConfigProvider>,
    pub conntrack: Arc<crate::conntrack::table::Conntrack>,
    pub policy_store: Arc<PolicySwap>,
    pub policy_engine: Arc<PolicyEngine>,
    pub zone_store: Arc<ZoneProvider>,
    pub zone_pair_store: Arc<ZonePairProvider>,
    pub zone_interface_store: Arc<crate::zones::provider::ZoneInterfaceProvider>,
    pub config_provider: Arc<AppConfigProvider>,
    /// Provider konfiguracji inspekcji DNS — zarządza trwałym przechowywaniem.
    pub dns_inspection_store: Arc<DnsInspectionConfigProvider>,
    /// Aktywna instancja agregatora inspekcji DNS — hot-swap przez `update_config`.
    pub dns_inspection: Arc<DnsInspection>,
    pub ips_store: Arc<IpsConfigProvider>,
    pub ips: Arc<Ips>,
    pub decision_engine: Arc<TlsDecisionEngine>,
    pub decryption_mirror: Arc<DecryptionMirror>,
    pub server_key_store: Arc<ServerKeyStore>,
    /// Detektor pinningu — wspoldzielony z TlsDecisionEngine do obserwacji stanu.
    pub pinning_detector: Arc<PinningDetector>,
    pub interface_monitor: Arc<Monitor>,
    pub interface_controller: Arc<Controller>,
    pub vlan_reconciler: Arc<crate::interfaces::VlanReconciler<Controller>>,
    pub interface_sniffer: Arc<crate::data_plane::interface_sniffer::InterfaceSniffer>,
    pub metrics_collector: Arc<MetricsCollector>,
    pub reset_lock: Arc<Mutex<()>>,
}

impl<PolicySwap, Monitor, Controller> Clone for QueryHandler<PolicySwap, Monitor, Controller>
where
    PolicySwap: PolicyManager,
    Monitor: InterfaceMonitor,
    Controller: InterfaceController,
{
    fn clone(&self) -> Self {
        Self {
            tcp_tracker: Arc::clone(&self.tcp_tracker),
            nat_engine: Arc::clone(&self.nat_engine),
            nat_store: Arc::clone(&self.nat_store),
            conntrack: Arc::clone(&self.conntrack),
            policy_store: Arc::clone(&self.policy_store),
            policy_engine: Arc::clone(&self.policy_engine),
            zone_store: Arc::clone(&self.zone_store),
            zone_pair_store: Arc::clone(&self.zone_pair_store),
            zone_interface_store: Arc::clone(&self.zone_interface_store),
            config_provider: Arc::clone(&self.config_provider),
            dns_inspection_store: Arc::clone(&self.dns_inspection_store),
            dns_inspection: Arc::clone(&self.dns_inspection),
            ips_store: Arc::clone(&self.ips_store),
            ips: Arc::clone(&self.ips),
            decision_engine: Arc::clone(&self.decision_engine),
            decryption_mirror: Arc::clone(&self.decryption_mirror),
            server_key_store: Arc::clone(&self.server_key_store),
            pinning_detector: Arc::clone(&self.pinning_detector),
            interface_monitor: Arc::clone(&self.interface_monitor),
            interface_controller: Arc::clone(&self.interface_controller),
            vlan_reconciler: Arc::clone(&self.vlan_reconciler),
            interface_sniffer: Arc::clone(&self.interface_sniffer),
            metrics_collector: Arc::clone(&self.metrics_collector),
            reset_lock: Arc::clone(&self.reset_lock),
        }
    }
}

fn parse_proto_collection<P, Id, V>(
    items: Vec<P>,
    converter: impl Fn(P) -> Result<(Id, V), anyhow::Error>,
    label: &str,
) -> Result<HashMap<Id, V>, Status>
where
    Id: Eq + std::hash::Hash,
{
    items
        .into_iter()
        .map(|item| {
            converter(item).map_err(|e| Status::invalid_argument(format!("invalid {label}: {e}")))
        })
        .collect()
}

fn decryption_mirror_config_from_proto(
    config: Option<&crate::proto::config::DecryptionMirrorConfig>,
) -> Result<DecryptionMirrorConfig, String> {
    let Some(config) = config else {
        return Ok(DecryptionMirrorConfig::default());
    };
    let max_session_bytes = if config.max_session_bytes == 0 {
        DecryptionMirrorConfig::default().max_session_bytes
    } else {
        config.max_session_bytes
    };
    let include_client_to_server = config.include_client_to_server || !config.include_server_to_client;
    let include_server_to_client = config.include_server_to_client || !config.include_client_to_server;

    if !config.enabled {
        return Ok(DecryptionMirrorConfig {
            enabled: false,
            target: None,
            include_client_to_server,
            include_server_to_client,
            forwarded_only: config.forwarded_only,
            max_session_bytes,
        });
    }

    let target_host = config.target_host.trim();
    if target_host.is_empty() {
        return Err("target_host is required when mirror is enabled".into());
    }
    if config.target_port == 0 || config.target_port > u16::MAX as u32 {
        return Err("target_port must be in range 1..65535 when mirror is enabled".into());
    }

    Ok(DecryptionMirrorConfig {
        enabled: true,
        target: Some(format!("{target_host}:{}", config.target_port)),
        include_client_to_server,
        include_server_to_client,
        forwarded_only: config.forwarded_only,
        max_session_bytes,
    })
}

#[tonic::async_trait]
impl<Swapper, Monitor, Controller> FirewallQueryService for QueryHandler<Swapper, Monitor, Controller>
where
    Swapper: PolicyManager + Send + Sync + 'static,
    Monitor: InterfaceMonitor + Send + Sync + 'static,
    Controller: InterfaceController + Send + Sync + 'static,
{
    async fn get_policies(
        &self,
        _request: Request<GetPoliciesRequest>,
    ) -> Result<Response<GetPoliciesResponse>, Status> {
        let rules = self
            .policy_store
            .get_policies()
            .iter()
            .map(|(id, pol)| pol.clone().into_rule(id.clone()))
            .collect::<Vec<_>>();

        Ok(Response::new(GetPoliciesResponse { rules }))
    }

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let id: PolicyId = Uuid::try_parse(&request.into_inner().id)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?
            .into();
        match self.policy_store.get_policy(&id) {
            Some(policy) => Ok(Response::new(GetPolicyResponse {
                rule: Some(policy.into_rule(id)),
            })),
            None => Err(Status::not_found(format!("policy with id {id} not found"))),
        }
    }

    async fn get_nat_bindings(
        &self,
        _request: Request<GetNatBindingsRequest>,
    ) -> Result<Response<GetNatBindingsResponse>, Status> {
        let bindings: Vec<crate::proto::services::NatBinding> = self.conntrack.iter_entries().into_iter()
            .filter_map(|entry| {
                let transform = entry.nat.lock().clone()?;
                let reply = entry.reply.lock().clone();

                Some(crate::proto::services::NatBinding {
                    binding_id: transform.binding_id,
                    rule_id: transform.rule_id,
                    original_src_ip: entry.original.src_ip.to_string(),
                    original_src_port: u32::from(entry.original.src_port),
                    original_dst_ip: entry.original.dst_ip.to_string(),
                    original_dst_port: u32::from(entry.original.dst_port),
                    translated_src_ip: reply.dst_ip.to_string(),
                    translated_src_port: u32::from(reply.dst_port),
                    translated_dst_ip: reply.src_ip.to_string(),
                    translated_dst_port: u32::from(reply.src_port),
                    protocol: entry.original.protocol as u8 as u32,
                })
            }).collect();

        Ok(Response::new(GetNatBindingsResponse { bindings }))
    }

    async fn get_zones(
        &self,
        _request: Request<GetZonesRequest>,
    ) -> Result<Response<GetZonesResponse>, Status> {
        let zones = self
            .zone_store
            .get_zones()
            .iter()
            .map(|(id, pol)| pol.clone().into_proto(id.clone()))
            .collect::<Vec<_>>();

        Ok(Response::new(GetZonesResponse { zones }))
    }

    async fn get_zone(
        &self,
        request: Request<GetZoneRequest>,
    ) -> Result<Response<GetZoneResponse>, Status> {
        let id = Uuid::try_parse(&request.into_inner().id)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?
            .into();
        match self.zone_store.get_zone(&id) {
            Some(policy) => Ok(Response::new(GetZoneResponse {
                zone: Some(policy.into_proto(id)),
            })),
            None => Err(Status::not_found(format!("policy with id {id} not found"))),
        }
    }

    async fn get_zone_interfaces(
        &self,
        _request: Request<crate::proto::services::GetZoneInterfacesRequest>,
    ) -> Result<Response<crate::proto::services::GetZoneInterfacesResponse>, Status> {
        let zone_interfaces = self
            .zone_interface_store
            .get_zone_interfaces()
            .iter()
            .map(|(id, zone_interface)| zone_interface.clone().into_proto(id.clone()))
            .collect();

        Ok(Response::new(
            crate::proto::services::GetZoneInterfacesResponse { zone_interfaces },
        ))
    }

    async fn get_zone_interface(
        &self,
        request: Request<crate::proto::services::GetZoneInterfaceRequest>,
    ) -> Result<Response<crate::proto::services::GetZoneInterfaceResponse>, Status> {
        let id: ZoneInterfaceId = Uuid::try_parse(&request.into_inner().id)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?
            .into();

        match self.zone_interface_store.get_zone_interface(&id) {
            Some(zone_interface) => Ok(Response::new(
                crate::proto::services::GetZoneInterfaceResponse {
                    zone_interface: Some(zone_interface.into_proto(id)),
                },
            )),
            None => Err(Status::not_found(format!("zone interface with id {id} not found"))),
        }
    }

    async fn get_live_zone_interfaces(
        &self,
        _request: Request<crate::proto::services::GetLiveZoneInterfacesRequest>,
    ) -> Result<Response<crate::proto::services::GetLiveZoneInterfacesResponse>, Status> {
        let zone_interfaces = self
            .zone_interface_store
            .get_live_zone_interfaces(&*self.interface_monitor)
            .into_iter()
            .map(|(id, zone_interface)| zone_interface.into_proto(id))
            .collect();

        Ok(Response::new(
            crate::proto::services::GetLiveZoneInterfacesResponse { zone_interfaces },
        ))
    }

    async fn get_zone_pairs(
        &self,
        _request: Request<GetZonePairsRequest>,
    ) -> Result<Response<GetZonePairsResponse>, Status> {
        let zone_pairs = self
            .zone_pair_store
            .get_zone_pairs()
            .iter()
            .map(|(id, pair)| pair.clone().into_proto(id.clone()))
            .collect::<Vec<_>>();

        Ok(Response::new(GetZonePairsResponse { zone_pairs }))
    }

    async fn get_zone_pair(
        &self,
        request: Request<GetZonePairRequest>,
    ) -> Result<Response<GetZonePairResponse>, Status> {
        let id = Uuid::try_parse(&request.into_inner().id)
            .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?
            .into();
        match self.zone_pair_store.get_zone_pair(&id) {
            Some(pair) => Ok(Response::new(GetZonePairResponse {
                zone_pair: Some(pair.into_proto(id)),
            })),
            None => Err(Status::not_found(format!(
                "zone pair with id {id} not found"
            ))),
        }
    }

    async fn get_system_time(
        &self,
        _request: Request<GetSystemTimeRequest>,
    ) -> Result<Response<GetSystemTimeResponse>, Status> {
        Ok(Response::new(GetSystemTimeResponse {
            time: Some(SystemTime::now().into()),
        }))
    }

    async fn get_pinning_stats(
        &self,
        _request: Request<GetPinningStatsRequest>,
    ) -> Result<Response<GetPinningStatsResponse>, Status> {
        let stats = self.pinning_detector.stats();
        Ok(Response::new(GetPinningStatsResponse {
            active_bypasses: stats.active_bypasses as u64,
            tracked_failures: stats.tracked_failures as u64,
        }))
    }

    async fn get_pinning_bypass(
        &self,
        request: Request<GetPinningBypassRequest>,
    ) -> Result<Response<GetPinningBypassResponse>, Status> {
        let req = request.into_inner();
        let source_ip = IpAddr::from_str(&req.source_ip).map_err(|e| {
            Status::invalid_argument(format!("invalid source_ip '{}': {e}", req.source_ip))
        })?;

        let response = match self.pinning_detector.bypass_detail(source_ip, &req.domain) {
            Some((reason, failure_count)) => GetPinningBypassResponse {
                found: true,
                reason: reason.to_string(),
                failure_count,
            },
            None => GetPinningBypassResponse {
                found: false,
                reason: String::new(),
                failure_count: 0,
            },
        };

        Ok(Response::new(response))
    }

    async fn set_interface_state(
        &self,
        request: Request<SetInterfaceStateRequest>,
    ) -> Result<Response<SetInterfaceStateResponse>, Status> {
        let req = request.into_inner();
        let id: ZoneInterfaceId = Uuid::try_parse(&req.id)
            .map_err(|e| Status::invalid_argument(format!("invalid id: {e}")))?
            .into();

        let _zone_interface = self.zone_interface_store.get_zone_interface(&id)
            .ok_or_else(|| Status::not_found(format!("zone interface with id {id} not found")))?;

        let os_name = self.zone_interface_store.resolve_os_name(&id)
            .ok_or_else(|| Status::not_found(format!("OS name for interface {id} could not be resolved")))?;

        let state = crate::proto::config::InterfaceAdministrativeState::try_from(req.state)
            .map_err(|e| Status::invalid_argument(format!("invalid state: {e}")))?;

        let up = matches!(state, crate::proto::config::InterfaceAdministrativeState::Up);

        self.interface_controller
            .set_interface_state(&os_name, up)
            .await
            .map_err(|e| Status::internal(format!("failed to set interface state: {e}")))?;

        Ok(Response::new(crate::proto::services::SetInterfaceStateResponse {}))
    }

    async fn update_physical_interface_properties(
        &self,
        request: Request<UpdatePhysicalInterfacePropertiesRequest>,
    ) -> Result<Response<UpdatePhysicalInterfacePropertiesResponse>, Status> {
        let req = request.into_inner();
        let id: ZoneInterfaceId = Uuid::try_parse(&req.id)
            .map_err(|e| Status::invalid_argument(format!("invalid id: {e}")))?
            .into();

        let zone_interface = self.zone_interface_store.get_zone_interface(&id)
            .ok_or_else(|| Status::not_found(format!("zone interface with id {id} not found")))?;

        // Validate that this is a physical interface
        if !matches!(zone_interface.kind, crate::zones::ZoneInterfaceKind::Physical(_)) {
            return Err(Status::invalid_argument(
                "Cannot update VLAN interface properties directly; VLANs are managed declaratively via bundle"
            ));
        }

        let os_name = self.zone_interface_store.resolve_os_name(&id)
            .ok_or_else(|| Status::not_found(format!("OS name for interface {id} could not be resolved")))?;

        self.interface_controller
            .set_interface_properties(
                &os_name,
                req.new_name.as_deref(),
                req.new_address.as_deref(),
            )
            .await
            .map_err(|e| Status::internal(format!("failed to set interface properties: {e}")))?;

        Ok(Response::new(UpdatePhysicalInterfacePropertiesResponse {
            message: "Physical interface properties updated successfully".to_string(),
        }))
    }
}

#[tonic::async_trait]
impl<Swapper, Monitor, Controller> FirewallConfigSnapshotService for QueryHandler<Swapper, Monitor, Controller>
where
    Swapper: PolicyManager + Send + Sync + 'static,
    Monitor: InterfaceMonitor + Send + Sync + 'static,
    Controller: InterfaceController + Send + Sync + 'static,
{
    async fn factory_reset(
        &self,
        request: Request<FactoryResetRequest>,
    ) -> Result<Response<FactoryResetResponse>, Status> {
        let inner = request.into_inner();
        let correlation_id = inner.correlation_id.clone();
        let options = FactoryResetOptions {
            clear_pki: inner.clear_pki.unwrap_or(true),
            clear_server_keys: inner.clear_server_keys.unwrap_or(true),
        };
        let _reset_guard = self.reset_lock.lock().await;

        tracing::warn!(
            event = "factory_reset.started",
            correlation_id,
            reason = %inner.reason,
            clear_pki = options.clear_pki,
            clear_server_keys = options.clear_server_keys,
            "factory reset requested"
        );

        if let Err(e) = self.apply_factory_safe_state().await {
            tracing::error!(event = "factory_reset.failed", correlation_id, error = %e, "failed to apply factory safe state");
            return Ok(Response::new(FactoryResetResponse {
                correlation_id,
                accepted: false,
                message: format!("failed to apply safe state: {e}"),
                safe_state_applied: false,
                removed_server_keys: 0,
                removed_server_key_files: 0,
                removed_ca_files: 0,
            }));
        }

        let mut report = FactoryResetReport {
            safe_state_applied: true,
            ..FactoryResetReport::default()
        };

        if let Err(e) = self.clear_factory_reset_materials(options, &mut report) {
            tracing::error!(event = "factory_reset.failed", correlation_id, error = %e, "failed to clear factory reset materials");
            return Ok(Response::new(FactoryResetResponse {
                correlation_id,
                accepted: false,
                message: format!("safe state applied, cleanup failed: {e}"),
                safe_state_applied: true,
                removed_server_keys: report.removed_server_keys,
                removed_server_key_files: report.removed_server_key_files,
                removed_ca_files: report.removed_ca_files,
            }));
        }

        tracing::warn!(
            event = "factory_reset.completed",
            correlation_id,
            removed_server_keys = report.removed_server_keys,
            removed_server_key_files = report.removed_server_key_files,
            removed_ca_files = report.removed_ca_files,
            "factory reset completed"
        );

        Ok(Response::new(FactoryResetResponse {
            correlation_id,
            accepted: true,
            message: String::new(),
            safe_state_applied: report.safe_state_applied,
            removed_server_keys: report.removed_server_keys,
            removed_server_key_files: report.removed_server_key_files,
            removed_ca_files: report.removed_ca_files,
        }))
    }

    #[allow(clippy::too_many_lines)]
    async fn push_active_config_snapshot(
        &self,
        request: Request<PushActiveConfigSnapshotRequest>,
    ) -> Result<Response<PushActiveConfigSnapshotResponse>, Status> {
        let inner = request.into_inner();
        let correlation_id = inner.correlation_id.clone();
        let _reset_guard = self.reset_lock.lock().await;

        // Extract snapshot_id before consuming the snapshot
        let snapshot = inner
            .snapshot
            .ok_or_else(|| Status::invalid_argument("missing snapshot"))?;
        let snapshot_id = snapshot.id.clone();
        let bundle = snapshot
            .bundle
            .ok_or_else(|| Status::invalid_argument("missing bundle in snapshot"))?;

        tracing::info!(policies=?bundle.rules, "pushing policies");

        tracing::info!(
            event = "config_snapshot.push.started",
            correlation_id,
            snapshot_id,
            rules = bundle.rules.len(),
            nat_rules = bundle.nat_rules.len(),
            zones = bundle.zones.len(),
            zone_pairs = bundle.zone_pairs.len(),
            zone_interfaces = bundle.zone_interfaces.len(),
            "received active config snapshot push"
        );

        // 1. Parse all proto types into domain-type HashMaps
        let policies = parse_proto_collection(bundle.rules, Policy::try_from_rule, "rule")?;
        let zones = parse_proto_collection(bundle.zones, Zone::try_from_proto, "zone")?;
        let zone_pairs =
            parse_proto_collection(bundle.zone_pairs, ZonePair::try_from_proto, "zone pair")?;
        let zone_interfaces = parse_proto_collection(
            bundle.zone_interfaces,
            ZoneInterface::try_from_proto,
            "zone interface",
        )?;
        NatRules::try_from_proto(crate::proto::config::NatRuleSet {
            items: bundle.nat_rules.clone(),
        })
        .map_err(|e| Status::invalid_argument(format!("invalid nat config: {e}")))?;

        // 2. Validate referential integrity across the entire bundle
        let errors = validate_bundle(&policies, &zone_pairs, &zones, &zone_interfaces);

        if !errors.is_empty() {
            let messages: Vec<String> = errors.iter().map(std::string::ToString::to_string).collect();
            tracing::warn!(
                event = "config_snapshot.push.rejected",
                correlation_id,
                snapshot_id,
                error_count = messages.len(),
                message = %messages.join("; "),
                "active config snapshot rejected by integrity validation"
            );
            return Ok(Response::new(PushActiveConfigSnapshotResponse {
                correlation_id,
                accepted: false,
                message: messages.join("; "),
                applied_snapshot_id: String::new(),
            }));
        }

        let bypass_domains: Vec<String> = bundle
            .ssl_bypass_list
            .iter()
            .map(|e| e.domain.clone())
            .collect();
        self.decision_engine.reload_bypass(&bypass_domains);

        if let Err(e) = self.reconcile_server_keys(&bundle.firewall_certificates) {
            tracing::error!(error = %e, "server key reconciliation failed");
            return Ok(Response::new(PushActiveConfigSnapshotResponse {
                correlation_id,
                accepted: false,
                message: format!("server key reconciliation failed: {e}"),
                applied_snapshot_id: String::new(),
            }));
        }

        if let Some(ref policy) = bundle.tls_inspection_policy {
            self.decision_engine.reload_ech_policy(EchTlsPolicy {
                block_ech_no_sni: policy.block_ech_no_sni,
                block_all_ech: policy.block_all_ech,
            });
            self.decision_engine
                .reload_known_pinned_domains(&policy.known_pinned_domains);
            let mirror_config = match decryption_mirror_config_from_proto(policy.decryption_mirror.as_ref()) {
                Ok(config) => config,
                Err(e) => {
                    tracing::error!(error = %e, "decryption mirror policy apply failed");
                    return Ok(Response::new(PushActiveConfigSnapshotResponse {
                        correlation_id,
                        accepted: false,
                        message: format!("decryption mirror policy apply failed: {e}"),
                        applied_snapshot_id: String::new(),
                    }));
                }
            };
            self.decryption_mirror.reload_config(mirror_config);
            if let Err(e) = self.apply_dns_ech_policy(policy).await {
                tracing::error!(error = %e, "DNS ECH policy apply failed");
                return Ok(Response::new(PushActiveConfigSnapshotResponse {
                    correlation_id,
                    accepted: false,
                    message: format!("dns ech policy apply failed: {e}"),
                    applied_snapshot_id: String::new(),
                }));
            }
        } else {
            self.decryption_mirror.reload_config(DecryptionMirrorConfig::default());
        }

        if let Err(e) = self.apply_nat_rules(&bundle.nat_rules).await {
            tracing::error!(error = %e, "NAT snapshot apply failed");
            return Ok(Response::new(PushActiveConfigSnapshotResponse {
                correlation_id,
                accepted: false,
                message: format!("nat snapshot apply failed: {e}"),
                applied_snapshot_id: String::new(),
            }));
        }

        if let Some(proto_app) = bundle.app_config.clone() {
            if let Err(e) = self.apply_app_config(proto_app).await {
                tracing::error!(error = %e, "AppConfig snapshot apply failed");
                return Ok(Response::new(PushActiveConfigSnapshotResponse {
                    correlation_id,
                    accepted: false,
                    message: format!("app config apply failed: {e}"),
                    applied_snapshot_id: String::new(),
                }));
            }
        }

        if let Some(proto_dns) = bundle.dns_inspection_config.clone() {
            if let Err(e) = self.apply_dns_inspection_config(proto_dns).await {
                tracing::error!(error = %e, "DnsInspectionConfig snapshot apply failed");
                return Ok(Response::new(PushActiveConfigSnapshotResponse {
                    correlation_id,
                    accepted: false,
                    message: format!("dns inspection config apply failed: {e}"),
                    applied_snapshot_id: String::new(),
                }));
            }
        }

        if let Some(proto_ips) = bundle.ips_config.clone() {
            if let Err(e) = self.apply_ips_config(proto_ips).await {
                tracing::error!(error = %e, "IpsConfig snapshot apply failed");
                return Ok(Response::new(PushActiveConfigSnapshotResponse {
                    correlation_id,
                    accepted: false,
                    message: format!("ips config apply failed: {e}"),
                    applied_snapshot_id: String::new(),
                }));
            }
        }

        self.zone_store
            .swap_zones(zones.into_iter().collect())
            .await
            .map_err(|e| Status::internal(format!("failed to swap zones: {e}")))?;

        // Capture old zone interfaces before swapping
        let old_zone_interfaces = self.zone_interface_store.get_zone_interfaces().clone();

        self.zone_interface_store
            .swap_zone_interfaces(zone_interfaces.into_iter().collect())
            .await
            .map_err(|e| Status::internal(format!("failed to swap zone interfaces: {e}")))?;

        let new_zone_interfaces = self.zone_interface_store.get_zone_interfaces();

        // VLAN reconciliation must run before sniffer so OS interfaces exist
        let reconciliation_errors = self.vlan_reconciler
            .reconcile(&old_zone_interfaces, &new_zone_interfaces)
            .await;
        if !reconciliation_errors.is_empty() {
            tracing::warn!(errors = ?reconciliation_errors, "VLAN reconciliation partial failures");
        }

        // Sniffer reconciliation
        let sniffed_names: Vec<String> = new_zone_interfaces
            .iter()
            .filter(|(_, zi)| zi.sniffed)
            .filter_map(|(id, _)| crate::zones::resolve_os_name(&new_zone_interfaces, id))
            .collect();
        self.interface_sniffer.reconcile_capture_interfaces(&sniffed_names);

        self.zone_pair_store
            .swap_zone_pairs(zone_pairs.into_iter().collect())
            .await
            .map_err(|e| Status::internal(format!("failed to swap zone pairs: {e}")))?;

        self.policy_store
            .swap_policies(policies.into_iter().collect())
            .await
            .map_err(|e| Status::internal(format!("failed to swap policies: {e}")))?;

        // Rebuild and swap the PolicyEngine evaluators using the new configuration.
        // We reload from stores because self.policy_store was just updated.
        let updated_policies = self.policy_store.get_policies();
        let updated_zone_pairs = self.zone_pair_store.get_zone_pairs();
        
        self.policy_engine
            .update_from_policies(&updated_policies, &updated_zone_pairs)
            .map_err(|e| Status::internal(format!("failed to rebuild policy engine: {e}")))?;

        tracing::info!(
            event = "config_snapshot.push.succeeded",
            correlation_id,
            snapshot_id,
            "active config snapshot applied"
        );

        Ok(Response::new(PushActiveConfigSnapshotResponse {
            correlation_id,
            accepted: true,
            message: String::new(),
            applied_snapshot_id: snapshot_id,
        }))
    }
}

impl<PolicySwap, Monitor, Controller> QueryHandler<PolicySwap, Monitor, Controller>
where
    PolicySwap: PolicyManager,
    Monitor: InterfaceMonitor,
    Controller: InterfaceController,
{
    async fn apply_factory_safe_state(&self) -> anyhow::Result<()> {
        self.policy_store
            .swap_policies(vec![default_drop_policy()?])
            .await?;

        let empty_domains: Vec<String> = Vec::new();
        self.decision_engine.reload_bypass(&empty_domains);
        self.decision_engine
            .reload_known_pinned_domains(&empty_domains);
        self.decision_engine.reload_ech_policy(EchTlsPolicy::default());

        self.apply_nat_rules(&[]).await?;

        let dns_config = DnsInspectionConfig::default();
        self.dns_inspection_store
            .swap_config(dns_config.clone())
            .await?;
        self.dns_inspection.update_config(&dns_config)?;

        let ips_config = IpsConfig::default();
        self.ips_store.swap_config(ips_config.clone()).await?;
        self.ips.update_config(&ips_config)?;

        self.zone_store.swap_zones(Vec::new()).await?;
        self.zone_interface_store
            .swap_zone_interfaces(Vec::new())
            .await?;
        self.zone_pair_store.swap_zone_pairs(Vec::new()).await?;

        let safe_config = {
            let current = self.config_provider.get_config();
            safe_app_config(current.as_ref())
        };
        self.config_provider.swap_config(safe_config).await?;

        tracing::warn!(event = "factory_reset.safe_state_applied", "factory reset safe state applied");
        Ok(())
    }

    fn clear_factory_reset_materials(
        &self,
        options: FactoryResetOptions,
        report: &mut FactoryResetReport,
    ) -> anyhow::Result<()> {
        if options.clear_server_keys {
            let key_report = self.server_key_store.clear_all()?;
            report.removed_server_keys = key_report.removed_entries;
            report.removed_server_key_files = key_report.removed_files;
        }

        if options.clear_pki {
            let config = self.config_provider.get_config();
            let ca_report = clear_ca_files(Path::new(&config.pki_dir))?;
            report.removed_ca_files = ca_report.removed_files;
        }

        Ok(())
    }

    async fn apply_nat_rules(
        &self,
        rules: &[crate::proto::config::NatRule],
    ) -> anyhow::Result<()> {
        let nat_config = NatConfig::from_proto_rules(rules)?;
        let runtime_rules = nat_config.to_runtime_rules()?;

        self.nat_store.swap_config(nat_config).await?;

        self.nat_engine.replace_rules(runtime_rules);
        Ok(())
    }

    async fn apply_dns_ech_policy(
        &self,
        policy: &crate::proto::config::TlsInspectionPolicy,
    ) -> anyhow::Result<()> {
        let current = self.dns_inspection_store.get_config();
        let mut new_config: DnsInspectionConfig = (**current).clone();
        new_config.ech_mitigation.strip_ech_dns = policy.strip_ech_dns;
        new_config.ech_mitigation.log_ech_attempts = policy.log_ech_attempts;
        self.dns_inspection_store
            .swap_config(new_config.clone())
            .await?;
        self.dns_inspection.update_config(&new_config)?;
        Ok(())
    }

    async fn apply_app_config(
        &self,
        proto: crate::proto::config::AppConfig,
    ) -> anyhow::Result<()> {
        let new_config = AppConfig::from_proto(proto)?;
        self.config_provider.swap_config(new_config).await?;
        Ok(())
    }

    async fn apply_dns_inspection_config(
        &self,
        proto: crate::proto::config::DnsInspectionConfig,
    ) -> anyhow::Result<()> {
        let new_config = DnsInspectionConfig::from_proto(proto)?;
        self.dns_inspection_store
            .swap_config(new_config.clone())
            .await?;
        self.dns_inspection.update_config(&new_config)?;
        Ok(())
    }

    async fn apply_ips_config(
        &self,
        proto: crate::proto::config::IpsConfig,
    ) -> anyhow::Result<()> {
        let new_config = IpsConfig::from_proto(proto)?;
        self.ips_store.swap_config(new_config.clone()).await?;
        self.ips.update_config(&new_config)?;
        Ok(())
    }

    fn reconcile_server_keys(
        &self,
        certs: &[crate::proto::config::FirewallCertificate],
    ) -> anyhow::Result<()> {
        let tls_server_certs: Vec<_> = certs
            .iter()
            .filter(|c| c.cert_type == CertificateType::TlsServer as i32)
            .collect();

        let current: std::collections::HashMap<SocketAddr, _> = self
            .server_key_store
            .list()
            .into_iter()
            .map(|entry| (entry.addr, entry))
            .collect();
        let mut desired = std::collections::HashMap::new();

        for cert in tls_server_certs {
            let addr = parse_bind_addr(cert)?;
            if desired.insert(addr, cert).is_some() {
                anyhow::bail!("duplicate TLS server certificate bind address: {addr}");
            }
        }

        let missing: Vec<String> = desired
            .iter()
            .filter(|(addr, cert)| match current.get(addr) {
                Some(e) => e.key_ref != cert.private_key_ref,
                None => true,
            })
            .map(|(_, cert)| cert.id.clone())
            .collect();

        if !missing.is_empty() {
            anyhow::bail!(
                "missing server keys on firewall (run UploadServerCertificate first): {}",
                missing.join(", ")
            );
        }

        for (addr, cert) in &desired {
            let existing = current
                .get(addr)
                .expect("missing entries rejected above");
            let desired_enabled = cert.is_active.unwrap_or(true);

            let metadata_changed = existing.fingerprint != cert.fingerprint
                || existing.certificate_pem != cert.certificate_pem
                || existing.common_name != cert.common_name
                || existing.bypass != cert.inspection_bypass;

            if metadata_changed {
                self.server_key_store.load(
                    *addr,
                    &cert.certificate_pem,
                    &cert.private_key_ref,
                    &cert.common_name,
                    &cert.fingerprint,
                    cert.inspection_bypass,
                    desired_enabled,
                )?;
                tracing::debug!(%addr, cn = %cert.common_name, "server key metadata refreshed");
            } else if existing.enabled != desired_enabled {
                self.server_key_store.set_enabled(*addr, desired_enabled)?;
            }
        }

        for entry in current.values() {
            if !desired.contains_key(&entry.addr) {
                let _ = self.server_key_store.remove(entry.addr, &entry.key_ref);
                tracing::info!(addr = %entry.addr, "removed server key not in desired state");
            }
        }

        Ok(())
    }
}

fn parse_bind_addr(cert: &crate::proto::config::FirewallCertificate) -> anyhow::Result<SocketAddr> {
    let ip = cert
        .bind_address
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind_address '{}': {e}", cert.bind_address))?;
    let port = if cert.bind_port == 0 {
        443
    } else {
        cert.bind_port as u16
    };
    Ok(SocketAddr::new(ip, port))
}

fn prepare_socket(socket_path: &str) -> std::io::Result<()> {
    let path = Path::new(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    Ok(())
}

fn cleanup_socket(socket_path: &str) {
    if let Err(e) = std::fs::remove_file(socket_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(socket = socket_path, error = %e, "failed to remove query socket");
    }
}
