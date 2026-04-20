use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
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
use crate::data_plane::nat::config::NatConfig;
use crate::data_plane::ips::config::IpsConfig;
use crate::data_plane::ips::ips::Ips;
use crate::data_plane::ips::provider::IpsConfigProvider;
use crate::data_plane::nat::{NatConfigProvider, NatEngine};
use crate::data_plane::tcp_session_tracker::TcpSessionTracker;
use crate::policy::provider::PolicyManager;
use crate::policy::{Policy, PolicyId};
use crate::proto::common::CertificateType;
use crate::proto::services::firewall_query_service_server::{
    FirewallQueryService, FirewallQueryServiceServer,
};
use crate::proto::services::firewall_config_snapshot_service_server::{
    FirewallConfigSnapshotService, FirewallConfigSnapshotServiceServer,
};
use crate::proto::services::{
    GetConfigRequest, GetConfigResponse, GetDnsInspectionConfigRequest,
    GetDnsInspectionConfigResponse, GetIpsConfigRequest, GetIpsConfigResponse,
    GetNatBindingsRequest, GetNatBindingsResponse, GetPinningBypassRequest,
    GetPinningBypassResponse, GetPinningStatsRequest, GetPinningStatsResponse, GetPoliciesRequest,
    GetPoliciesResponse, GetPolicyRequest, GetPolicyResponse, GetTcpSessionsRequest,
    GetTcpSessionsResponse, GetZonePairRequest, GetZonePairResponse, GetZonePairsRequest,
    GetZonePairsResponse, GetZoneRequest, GetZoneResponse, GetZonesRequest, GetZonesResponse,
    SwapConfigRequest, SwapConfigResponse, SwapDnsInspectionConfigRequest,
    SwapDnsInspectionConfigResponse, SwapIpsConfigRequest, SwapIpsConfigResponse,
    GetSystemTimeRequest, GetSystemTimeResponse, PushActiveConfigSnapshotRequest,
    PushActiveConfigSnapshotResponse,
};
use crate::tls::pinning_detector::PinningDetector;
use crate::tls::{EchTlsPolicy, ServerKeyStore, TlsDecisionEngine};
use crate::zones::Zone;
use crate::zones::provider::{ZonePairProvider, ZoneProvider};
use crate::zones::{ZonePair, ZoneInterface};

pub struct QueryServer<PolicySwap>
where
    PolicySwap: PolicyManager + Send + Sync,
{
    handler: QueryHandler<PolicySwap>,
    socket_path: String,
    shutdown: CancellationToken,
}

impl<PolicySwap> QueryServer<PolicySwap>
where
    PolicySwap: PolicyManager + Send + Sync + 'static,
{
    pub fn new(
        handler: QueryHandler<PolicySwap>,
        socket_path: impl Into<String>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            handler,
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
            .add_service(FirewallConfigSnapshotServiceServer::new(self.handler))
            .serve_with_incoming_shutdown(incoming, self.shutdown.cancelled())
            .await
        {
            tracing::error!(error = %e, "FirewallQueryService server error");
        }

        cleanup_socket(&self.socket_path);
    }
}

pub struct QueryHandler<PolicySwap>
where
    PolicySwap: PolicyManager,
{
    pub tcp_tracker: Arc<TcpSessionTracker>,
    pub nat_engine: Arc<Mutex<NatEngine>>,
    pub nat_store: Arc<NatConfigProvider>,
    pub policy_store: Arc<PolicySwap>,
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
    pub server_key_store: Arc<ServerKeyStore>,
    /// Detektor pinningu — wspoldzielony z TlsDecisionEngine do obserwacji stanu.
    pub pinning_detector: Arc<PinningDetector>,
}

impl<PolicySwap> Clone for QueryHandler<PolicySwap>
where
    PolicySwap: PolicyManager,
{
    fn clone(&self) -> Self {
        Self {
            tcp_tracker: Arc::clone(&self.tcp_tracker),
            nat_engine: Arc::clone(&self.nat_engine),
            nat_store: Arc::clone(&self.nat_store),
            policy_store: Arc::clone(&self.policy_store),
            zone_store: Arc::clone(&self.zone_store),
            zone_pair_store: Arc::clone(&self.zone_pair_store),
            zone_interface_store: Arc::clone(&self.zone_interface_store),
            config_provider: Arc::clone(&self.config_provider),
            dns_inspection_store: Arc::clone(&self.dns_inspection_store),
            dns_inspection: Arc::clone(&self.dns_inspection),
            ips_store: Arc::clone(&self.ips_store),
            ips: Arc::clone(&self.ips),
            decision_engine: Arc::clone(&self.decision_engine),
            server_key_store: Arc::clone(&self.server_key_store),
            pinning_detector: Arc::clone(&self.pinning_detector),
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

#[tonic::async_trait]
impl<Swapper> FirewallQueryService for QueryHandler<Swapper>
where
    Swapper: PolicyManager + Send + Sync + 'static,
{
    async fn get_tcp_sessions(
        &self,
        _request: Request<GetTcpSessionsRequest>,
    ) -> Result<Response<GetTcpSessionsResponse>, Status> {
        Err(Status::unimplemented("not yet implemented"))
    }

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
        Err(Status::unimplemented("not yet implemented"))
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

    async fn swap_config(
        &self,
        request: Request<SwapConfigRequest>,
    ) -> Result<Response<SwapConfigResponse>, Status> {
        let proto_config = request
            .into_inner()
            .config
            .ok_or_else(|| Status::invalid_argument("missing config field"))?;

        let new_config = AppConfig::from_proto(proto_config)
            .map_err(|e| Status::invalid_argument(format!("invalid config: {e}")))?;

        tracing::info!(
            event = "config.swap.started",
            capture_interfaces = ?new_config.capture_interfaces,
            query_socket_path = %new_config.query_socket_path,
            event_socket_path = %new_config.event_socket_path,
            "received AppConfig swap request"
        );

        self.config_provider
            .swap_config(new_config)
            .await
            .map_err(|e| Status::internal(format!("failed to swap config: {e}")))?;

        tracing::info!(
            event = "config.swap.succeeded",
            "AppConfig swap request applied"
        );

        Ok(Response::new(SwapConfigResponse {}))
    }

    async fn get_config(
        &self,
        _request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        let config = self.config_provider.get_config();
        Ok(Response::new(GetConfigResponse {
            config: Some(config.to_proto()),
        }))
    }

    async fn get_system_time(
        &self,
        _request: Request<GetSystemTimeRequest>,
    ) -> Result<Response<GetSystemTimeResponse>, Status> {
        Ok(Response::new(GetSystemTimeResponse {
            time: Some(SystemTime::now().into()),
        }))
    }

    async fn swap_dns_inspection_config(
        &self,
        request: Request<SwapDnsInspectionConfigRequest>,
    ) -> Result<Response<SwapDnsInspectionConfigResponse>, Status> {
        let proto_config = request
            .into_inner()
            .config
            .ok_or_else(|| Status::invalid_argument("missing config field in request"))?;

        let new_config = DnsInspectionConfig::from_proto(proto_config)
            .map_err(|e| Status::invalid_argument(format!("invalid dns inspection config: {e}")))?;

        tracing::info!(
            event = "dns_inspection.swap.started",
            enabled = new_config.general.enabled,
            blocklist_domains = new_config.blocklist.domains.len(),
            dns_tunneling_enabled = new_config.dns_tunneling.enabled,
            dnssec_enabled = new_config.dnssec.enabled,
            "received DNS inspection config swap request"
        );

        self.dns_inspection_store
            .swap_config(new_config.clone())
            .await
            .map_err(|e| Status::internal(format!("failed to save dns inspection config: {e}")))?;

        self.dns_inspection
            .update_config(&new_config)
            .map_err(|e| Status::internal(format!("failed to apply dns inspection config: {e}")))?;

        tracing::info!(
            event = "dns_inspection.swap.succeeded",
            enabled = new_config.general.enabled,
            "DNS inspection config applied"
        );

        Ok(Response::new(SwapDnsInspectionConfigResponse {}))
    }

    async fn get_dns_inspection_config(
        &self,
        _request: Request<GetDnsInspectionConfigRequest>,
    ) -> Result<Response<GetDnsInspectionConfigResponse>, Status> {
        let config = self.dns_inspection_store.get_config();
        Ok(Response::new(GetDnsInspectionConfigResponse {
            config: Some(config.to_proto()),
        }))
    }

    async fn swap_ips_config(
        &self,
        request: Request<SwapIpsConfigRequest>,
    ) -> Result<Response<SwapIpsConfigResponse>, Status> {
        let proto_config = request
            .into_inner()
            .config
            .ok_or_else(|| Status::invalid_argument("missing config field in request"))?;

        let new_config = IpsConfig::from_proto(proto_config)
            .map_err(|e| Status::invalid_argument(format!("invalid ips config: {e}")))?;

        tracing::info!(
            event = "ips.swap.started",
            enabled = new_config.general.enabled,
            detection_enabled = new_config.detection.enabled,
            signatures = new_config.signatures.len(),
            "received IPS config swap request"
        );

        self.ips_store
            .swap_config(new_config.clone())
            .await
            .map_err(|e| Status::internal(format!("failed to save ips config: {e}")))?;

        self.ips
            .update_config(&new_config)
            .map_err(|e| Status::internal(format!("failed to apply ips config: {e}")))?;

        tracing::info!(
            event = "ips.swap.succeeded",
            enabled = new_config.general.enabled,
            signatures = new_config.signatures.len(),
            "IPS config applied"
        );

        Ok(Response::new(SwapIpsConfigResponse {}))
    }

    async fn get_ips_config(
        &self,
        _request: Request<GetIpsConfigRequest>,
    ) -> Result<Response<GetIpsConfigResponse>, Status> {
        let config = self.ips_store.get_config();
        Ok(Response::new(GetIpsConfigResponse {
            config: Some(config.to_proto()),
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
}

#[tonic::async_trait]
impl<Swapper> FirewallConfigSnapshotService for QueryHandler<Swapper>
where
    Swapper: PolicyManager + Send + Sync + 'static,
{
    async fn push_active_config_snapshot(
        &self,
        request: Request<PushActiveConfigSnapshotRequest>,
    ) -> Result<Response<PushActiveConfigSnapshotResponse>, Status> {
        let inner = request.into_inner();
        let correlation_id = inner.correlation_id.clone();

        // Extract snapshot_id before consuming the snapshot
        let snapshot = inner
            .snapshot
            .ok_or_else(|| Status::invalid_argument("missing snapshot"))?;
        let snapshot_id = snapshot.id.clone();
        let bundle = snapshot
            .bundle
            .ok_or_else(|| Status::invalid_argument("missing bundle in snapshot"))?;

        tracing::info!(
            event = "config_snapshot.push.started",
            correlation_id,
            snapshot_id,
            rules = bundle.rules.len(),
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

        // 2. Validate referential integrity across the entire bundle
        let errors =
            crate::integrity::validate_bundle(&policies, &zone_pairs, &zones, &zone_interfaces);

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
            if let Err(e) = self.apply_dns_ech_policy(policy).await {
                tracing::error!(error = %e, "DNS ECH policy apply failed");
                return Ok(Response::new(PushActiveConfigSnapshotResponse {
                    correlation_id,
                    accepted: false,
                    message: format!("dns ech policy apply failed: {e}"),
                    applied_snapshot_id: String::new(),
                }));
            }
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

        self.zone_store
            .swap_zones(zones.into_iter().collect())
            .await
            .map_err(|e| Status::internal(format!("failed to swap zones: {e}")))?;

        self.zone_interface_store
            .swap_zone_interfaces(zone_interfaces.into_iter().collect())
            .await
            .map_err(|e| Status::internal(format!("failed to swap zone interfaces: {e}")))?;

        self.zone_pair_store
            .swap_zone_pairs(zone_pairs.into_iter().collect())
            .await
            .map_err(|e| Status::internal(format!("failed to swap zone pairs: {e}")))?;

        self.policy_store
            .swap_policies(policies.into_iter().collect())
            .await
            .map_err(|e| Status::internal(format!("failed to swap policies: {e}")))?;

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

impl<PolicySwap> QueryHandler<PolicySwap>
where
    PolicySwap: PolicyManager,
{
    async fn apply_nat_rules(
        &self,
        rules: &[crate::proto::config::NatRule],
    ) -> anyhow::Result<()> {
        let nat_config = NatConfig::from_proto_rules(rules)?;
        let runtime_rules = nat_config.to_runtime_rules()?;

        self.nat_store.swap_config(nat_config).await?;

        let mut engine = self.nat_engine.lock().await;
        engine.replace_rules(&runtime_rules);
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
